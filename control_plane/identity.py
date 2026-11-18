"""Account, course and environment policy over current PostgreSQL facts.

The public mutation methods own one fenced transaction each. Predicate functions
also work in an existing transaction so admission, credentials and execution
can check the same policy at their own persistence boundaries.
"""
from contextlib import contextmanager
import hashlib
import hmac
import json
import secrets

from sqlalchemy import text

from .plugins.sdk import AuthorizationDenied


def _label(value):
    if not isinstance(value, str) or not value.strip() or len(value) > 255 or "\x00" in value:
        raise ValueError("a nonempty name of at most 255 characters is required")
    return value.strip()


def _password_bytes(password):
    if not isinstance(password, str) or not 1 <= len(password) <= 1024:
        raise ValueError("invalid password length")
    return password.encode("utf-8")


def _digest(password, salt):
    return hashlib.scrypt(_password_bytes(password), salt=salt, n=32768, r=8, p=1,
                          maxmem=64 * 1024 * 1024, dklen=32)


def _hash_password(password):
    salt = secrets.token_bytes(16)
    return f"scrypt:32768:8:1${salt.hex()}${_digest(password, salt).hex()}"


def verify_password(password, encoded):
    """Accept only the service's bounded work factor and digest format."""
    try:
        method, salt, expected = encoded.split("$")
        if method != "scrypt:32768:8:1" or len(salt) != 32 or len(expected) != 64:
            return False
        return hmac.compare_digest(_digest(password, bytes.fromhex(salt)), bytes.fromhex(expected))
    except (AttributeError, TypeError, ValueError, UnicodeError):
        return False


def active_role(uow, actor_id):
    return uow.scalar(text("""
        SELECT role FROM control_plane.users WHERE id=:id AND active AND deleted_at IS NULL
    """), {"id": actor_id})


def can_manage_course(uow, actor_id, course_id):
    return bool(uow.scalar(text("""
        SELECT EXISTS(SELECT FROM control_plane.courses c, control_plane.users u
        WHERE c.id=:course AND u.id=:actor AND u.active AND u.deleted_at IS NULL
          AND c.deleted_at IS NULL
          AND (u.role='admin' OR (u.role='teacher' AND c.owner_teacher_id=u.id)))
    """), {"actor": actor_id, "course": course_id}))


# Reuse precisely the same join for authorizing access and detecting loss of
# the last effective path after a mutation. A retained membership row with
# left_at set does not authorize, even when an assignment remains in history.
_STUDENT_PATHS = """
    SELECT DISTINCT m.student_id, a.environment_id, m.course_id
    FROM control_plane.environment_assignments a
    JOIN control_plane.environments e ON e.id=a.environment_id
    JOIN control_plane.courses c ON c.id=e.course_id
    JOIN control_plane.course_members m ON m.course_id=c.id
    JOIN control_plane.users s ON s.id=m.student_id
    LEFT JOIN control_plane.groups g ON g.id=m.group_id AND g.course_id=m.course_id
    WHERE s.role='student' AND s.active AND s.deleted_at IS NULL
      AND c.deleted_at IS NULL AND e.deleted_at IS NULL AND e.lifecycle <> 'deleted'
      AND m.left_at IS NULL AND a.revoked_at IS NULL
      AND (a.student_id=m.student_id OR (a.group_id=g.id AND g.deleted_at IS NULL))
"""


def can_access_environment(uow, actor_id, environment_id, *, manage=False, roles=None):
    role = uow.scalar(text(f"""
        SELECT u.role FROM control_plane.users u, control_plane.environments e
        JOIN control_plane.courses c ON c.id=e.course_id
        WHERE u.id=:actor AND u.active AND u.deleted_at IS NULL AND e.id=:env
          AND e.deleted_at IS NULL AND e.lifecycle <> 'deleted' AND c.deleted_at IS NULL
          AND (u.role='admin' OR (u.role='teacher' AND u.id=e.owner_teacher_id)
               OR (NOT :manage AND u.role='student' AND EXISTS
                   (SELECT FROM ({_STUDENT_PATHS}) p
                    WHERE p.student_id=u.id AND p.environment_id=e.id)))
    """), {"actor": actor_id, "env": environment_id, "manage": manage})
    return role is not None and (roles is None or (
        isinstance(roles, (tuple, list, set, frozenset)) and role in roles))


def can_read_environment_status(uow, actor_id, environment_id, *, manage=False):
    """Owners and administrators retain access to the history of a deleted environment."""
    if can_access_environment(uow, actor_id, environment_id, manage=manage):
        return True
    return bool(uow.scalar(text("""
        SELECT EXISTS(SELECT FROM control_plane.users u, control_plane.environments e
        WHERE e.id=:env AND (e.deleted_at IS NOT NULL OR e.lifecycle='deleted')
          AND u.id=:actor AND u.active AND u.deleted_at IS NULL
          AND (u.role='admin' OR (u.role='teacher' AND u.id=e.owner_teacher_id)))
    """), {"env": environment_id, "actor": actor_id}))


def _authorized_status(uow, actor_id, query, object_id):
    row = uow.execute(text(query), {"id": object_id}).mappings().first()
    if row is None or not can_read_environment_status(uow, actor_id, row["environment_id"]):
        raise AuthorizationDenied()
    return dict(row)


def _audit(uow, actor_id, action, *, env=None, **ids):
    # Callers supply identifiers and fixed role names, never credentials or free-form text.
    uow.execute(text("""
        INSERT INTO control_plane.audit_events(actor_id,environment_id,action,result,data)
        VALUES (:actor,:env,:action,'succeeded',CAST(:data AS jsonb))
    """), {"actor": actor_id, "env": env, "action": action,
           "data": json.dumps({key: str(value) for key, value in ids.items() if value is not None})})


@contextmanager
def _track_student_access(uow, actor_id, *, student_id=None, course_id=None, environment_id=None):
    where = {"student_id": student_id, "course_id": course_id, "environment_id": environment_id}
    binds = {k: v for k, v in where.items() if v is not None}
    query = text(f"SELECT student_id, environment_id FROM ({_STUDENT_PATHS}) paths WHERE " +
                 " AND ".join(f"{k}=:{k}" for k in binds))
    before = set(uow.execute(query, binds))
    yield
    if before:
        from .credentials import record_access_loss
        for student, environment in before.difference(uow.execute(query, binds)):
            record_access_loss(uow, actor_id, student, environment)


def _managed_course(uow, actor_id, course_id):
    course = uow.execute(text("""
        SELECT c.id, c.owner_teacher_id FROM control_plane.courses c, control_plane.users u
        WHERE c.id=:course AND c.deleted_at IS NULL AND u.id=:actor AND u.active
          AND u.deleted_at IS NULL
          AND (u.role='admin' OR (u.role='teacher' AND u.id=c.owner_teacher_id))
        FOR UPDATE OF c
    """), {"course": course_id, "actor": actor_id}).first()
    if course is None:
        raise AuthorizationDenied()
    return course


def _group_in_course(uow, group_id, course_id):
    if not uow.scalar(text("""SELECT EXISTS (SELECT FROM control_plane.groups
                             WHERE id=:group AND course_id=:course AND deleted_at IS NULL)"""),
                      {"group": group_id, "course": course_id}):
        raise ValueError("group is not active in this course")


def _account(uow, actor_id, user_id, *, personal=False):
    target = uow.execute(text("""
        SELECT id, username, role, created_by, exclusive_management, active, deleted_at
        FROM control_plane.users WHERE id=:target AND deleted_at IS NULL FOR UPDATE
    """), {"target": user_id}).first()
    role = active_role(uow, actor_id)
    if target is not None and role is not None:
        if role == "admin" or (personal and str(target.id) == str(actor_id)):
            return target
        if (role == "teacher" and target.role == "student" and target.exclusive_management
                and str(target.created_by) == str(actor_id)):
            return target
    raise AuthorizationDenied()


class IdentityService:
    def __init__(self, runtime):
        self.runtime = runtime

    def environment_status(self, actor_id, environment_id):
        with self.runtime.fenced_transaction() as uow:
            return _authorized_status(uow, actor_id, """
                SELECT id AS environment_id,name,lifecycle,course_id,template_version_id,updated_at
                FROM control_plane.environments WHERE id=:id
            """, environment_id)

    def resource_status(self, actor_id, resource_id):
        from .workflows import resource_state

        with self.runtime.fenced_transaction() as uow:
            row = _authorized_status(uow, actor_id, """
                SELECT id AS resource_id,environment_id,name,type_label
                FROM control_plane.experiment_resources WHERE id=:id
            """, resource_id)
            return {**row, **resource_state(uow, resource_id)}

    def job_status(self, actor_id, job_id):
        with self.runtime.fenced_transaction() as uow:
            return _authorized_status(uow, actor_id, """
                SELECT id AS job_id,environment_id,kind,state,created_at,updated_at,finished_at
                FROM control_plane.jobs WHERE id=:id
            """, job_id)

    def create_user(self, actor_id, username, password, *, role="student"):
        username, hashed = _label(username), _hash_password(password)
        with self.runtime.fenced_transaction() as uow:
            creator_role = active_role(uow, actor_id)
            if role not in {"admin", "teacher", "student"}:
                raise ValueError("unknown account role")
            if creator_role != "admin" and (creator_role != "teacher" or role != "student"):
                raise AuthorizationDenied()
            user_id = uow.scalar(text("""
                INSERT INTO control_plane.users(username,password_hash,role,created_by,exclusive_management)
                VALUES (:name,:hashed,:role,:actor,:exclusive) RETURNING id
            """), {"name": username, "hashed": hashed, "role": role, "actor": actor_id,
                   "exclusive": creator_role == "teacher"})
            _audit(uow, actor_id, "account.create", user_id=user_id)
            return user_id

    def get_user(self, actor_id, user_id):
        with self.runtime.fenced_transaction() as uow:
            return dict(_account(uow, actor_id, user_id, personal=True)._mapping)

    def rename_user(self, actor_id, user_id, username):
        with self.runtime.fenced_transaction() as uow:
            _account(uow, actor_id, user_id, personal=True)
            uow.execute(text("UPDATE control_plane.users SET username=:name WHERE id=:id"),
                        {"name": _label(username), "id": user_id})
            _audit(uow, actor_id, "account.rename", user_id=user_id)

    def reset_password(self, actor_id, user_id, password):
        hashed = _hash_password(password)
        with self.runtime.fenced_transaction() as uow:
            _account(uow, actor_id, user_id)
            self._write_password(uow, actor_id, user_id, hashed, "account.reset_password")

    def change_password(self, actor_id, current_password, new_password):
        hashed = _hash_password(new_password)
        with self.runtime.fenced_transaction() as uow:
            _account(uow, actor_id, actor_id, personal=True)
            stored = uow.scalar(text("SELECT password_hash FROM control_plane.users WHERE id=:id"),
                                {"id": actor_id})
            if not verify_password(current_password, stored):
                raise AuthorizationDenied()
            self._write_password(uow, actor_id, actor_id, hashed, "account.change_password")

    @staticmethod
    def _write_password(uow, actor_id, user_id, hashed, action):
        uow.execute(text("UPDATE control_plane.users SET password_hash=:hash WHERE id=:id"),
                    {"id": user_id, "hash": hashed})
        _audit(uow, actor_id, action, user_id=user_id)

    def set_role(self, actor_id, user_id, role):
        if role not in ("admin", "teacher", "student"):
            raise ValueError("unknown account role")
        with self.runtime.fenced_transaction() as uow:
            if active_role(uow, actor_id) != "admin":
                raise AuthorizationDenied()
            account = _account(uow, actor_id, user_id)
            if account.role == role:
                return
            # An account cannot become a non-teacher while still responsible for
            # a course, or leave the student role while enrolled. Handle those
            # relationships explicitly; changing a role must not destroy them.
            if account.role == "teacher" and uow.scalar(text("""
                    SELECT EXISTS (SELECT FROM control_plane.courses
                                   WHERE owner_teacher_id=:id AND deleted_at IS NULL)
            """), {"id": account.id}):
                raise ValueError("teacher still owns courses")
            if account.role == "student" and uow.scalar(text("""
                    SELECT EXISTS (SELECT FROM control_plane.course_members m
                                   JOIN control_plane.courses c ON c.id=m.course_id
                                   WHERE m.student_id=:id AND m.left_at IS NULL AND c.deleted_at IS NULL)
            """), {"id": account.id}):
                raise ValueError("student still enrolled in courses")
            uow.execute(text("""
                UPDATE control_plane.users SET role=:role, exclusive_management=false WHERE id=:id
            """), {"role": role, "id": account.id})
            _audit(uow, actor_id, "account.change_role", user_id=user_id,
                   previous_role=account.role, new_role=role)

    def set_active(self, actor_id, user_id, active):
        if not isinstance(active, bool):
            raise ValueError("active must be boolean")
        with self.runtime.fenced_transaction() as uow:
            _account(uow, actor_id, user_id)
            with _track_student_access(uow, actor_id, student_id=user_id):
                uow.execute(text("UPDATE control_plane.users SET active=:active WHERE id=:id"),
                            {"id": user_id, "active": active})
            _audit(uow, actor_id, "account.enable" if active else "account.disable", user_id=user_id)

    def delete_user(self, actor_id, user_id):
        with self.runtime.fenced_transaction() as uow:
            _account(uow, actor_id, user_id)
            with _track_student_access(uow, actor_id, student_id=user_id):
                uow.execute(text("""
                    UPDATE control_plane.users SET active=false,deleted_at=clock_timestamp() WHERE id=:id
                """), {"id": user_id})
            _audit(uow, actor_id, "account.delete", user_id=user_id)

    def create_course(self, actor_id, owner_teacher_id, name):
        with self.runtime.fenced_transaction() as uow:
            actor_role = active_role(uow, actor_id)
            if actor_role != "admin" and not (actor_role == "teacher" and str(actor_id) == str(owner_teacher_id)):
                raise AuthorizationDenied()
            if active_role(uow, owner_teacher_id) != "teacher":
                raise ValueError("course owner must be an active teacher")
            course = uow.scalar(text("""
                INSERT INTO control_plane.courses(owner_teacher_id,name) VALUES (:owner,:name) RETURNING id
            """), {"owner": owner_teacher_id, "name": _label(name)})
            _audit(uow, actor_id, "course.create", course_id=course)
            return course

    def create_group(self, actor_id, course_id, name):
        with self.runtime.fenced_transaction() as uow:
            _managed_course(uow, actor_id, course_id)
            group = uow.scalar(text("""
                INSERT INTO control_plane.groups(course_id,name) VALUES (:course,:name) RETURNING id
            """), {"course": course_id, "name": _label(name)})
            _audit(uow, actor_id, "group.create", course_id=course_id, group_id=group)
            return group

    def delete_course(self, actor_id, course_id):
        with self.runtime.fenced_transaction() as uow:
            _managed_course(uow, actor_id, course_id)
            if uow.scalar(text("SELECT EXISTS (SELECT FROM control_plane.environments WHERE course_id=:id)"),
                          {"id": course_id}):
                raise ValueError("course has retained environment or execution history")
            uow.execute(text("UPDATE control_plane.courses SET deleted_at=clock_timestamp() WHERE id=:id"),
                        {"id": course_id})
            _audit(uow, actor_id, "course.delete", course_id=course_id)

    def delete_group(self, actor_id, course_id, group_id):
        with self.runtime.fenced_transaction() as uow:
            _managed_course(uow, actor_id, course_id)
            _group_in_course(uow, group_id, course_id)
            with _track_student_access(uow, actor_id, course_id=course_id):
                params = {"group": group_id, "course": course_id}
                uow.execute(text("""UPDATE control_plane.environment_assignments SET revoked_at=clock_timestamp()
                                    WHERE group_id=:group AND course_id=:course AND revoked_at IS NULL"""), params)
                uow.execute(text("""UPDATE control_plane.course_members SET group_id=NULL
                                    WHERE group_id=:group AND course_id=:course"""), params)
                uow.execute(text("UPDATE control_plane.groups SET deleted_at=clock_timestamp() WHERE id=:group"),
                            params)
            _audit(uow, actor_id, "group.delete", course_id=course_id, group_id=group_id)

    def enroll(self, actor_id, course_id, student_id, *, group_id=None):
        with self.runtime.fenced_transaction() as uow:
            course = _managed_course(uow, actor_id, course_id)
            params = {"course": course_id, "student": student_id, "actor": actor_id, "group": group_id}
            student = uow.execute(text("""
                SELECT created_by,exclusive_management FROM control_plane.users
                WHERE id=:student AND role='student' AND active AND deleted_at IS NULL FOR UPDATE
            """), params).first()
            if student is None:
                raise ValueError("active student required")
            if group_id is not None:
                _group_in_course(uow, group_id, course_id)
            member = uow.scalar(text("""
                INSERT INTO control_plane.course_members(course_id,student_id,group_id,added_by)
                VALUES (:course,:student,:group,:actor)
                ON CONFLICT(course_id,student_id) DO UPDATE SET left_at=NULL,group_id=EXCLUDED.group_id,
                    added_by=EXCLUDED.added_by,joined_at=clock_timestamp()
                WHERE control_plane.course_members.left_at IS NOT NULL RETURNING id
            """), params)
            if member is None:
                raise ValueError("student already enrolled in this course")
            if student.exclusive_management and student.created_by != course.owner_teacher_id:
                uow.execute(text("UPDATE control_plane.users SET exclusive_management=false WHERE id=:student"), params)
                _audit(uow, actor_id, "account.share", user_id=student_id, course_id=course_id)
            _audit(uow, actor_id, "course.enroll", course_id=course_id, student_id=student_id)
            return member

    def move_student(self, actor_id, course_id, student_id, group_id):
        with self.runtime.fenced_transaction() as uow:
            _managed_course(uow, actor_id, course_id)
            if group_id is not None:
                _group_in_course(uow, group_id, course_id)
            with _track_student_access(uow, actor_id, course_id=course_id, student_id=student_id):
                moved = uow.scalar(text("""
                    UPDATE control_plane.course_members SET group_id=:group
                    WHERE course_id=:course AND student_id=:student AND left_at IS NULL RETURNING id
                """), {"group": group_id, "course": course_id, "student": student_id})
                if moved is None:
                    raise ValueError("current course membership required")
            _audit(uow, actor_id, "course.move_group", course_id=course_id, student_id=student_id, group_id=group_id)

    def leave_course(self, actor_id, course_id, student_id):
        with self.runtime.fenced_transaction() as uow:
            _managed_course(uow, actor_id, course_id)
            params = {"course": course_id, "student": student_id}
            with _track_student_access(uow, actor_id, course_id=course_id, student_id=student_id):
                left = uow.scalar(text("""
                    UPDATE control_plane.course_members SET left_at=clock_timestamp(),group_id=NULL
                    WHERE course_id=:course AND student_id=:student AND left_at IS NULL RETURNING id
                """), params)
                if left is None:
                    raise ValueError("current course membership required")
                uow.execute(text("""
                    UPDATE control_plane.environment_assignments SET revoked_at=clock_timestamp()
                    WHERE course_id=:course AND student_id=:student AND revoked_at IS NULL
                """), params)
            _audit(uow, actor_id, "course.leave", course_id=course_id, student_id=student_id)

    def assign(self, actor_id, environment_id, *, student_id=None, group_id=None):
        if (student_id is None) == (group_id is None):
            raise ValueError("assign one student or one group")
        with self.runtime.fenced_transaction() as uow:
            course = uow.scalar(text("""
                SELECT course_id FROM control_plane.environments
                WHERE id=:env AND deleted_at IS NULL AND lifecycle<>'deleted'
            """), {"env": environment_id})
            _managed_course(uow, actor_id, course)
            params = {"env": environment_id, "group": group_id, "student": student_id,
                      "actor": actor_id, "course": course}
            if group_id is not None:
                _group_in_course(uow, group_id, course)
            elif not uow.scalar(text("""
                SELECT EXISTS(SELECT FROM control_plane.course_members m JOIN control_plane.users s ON s.id=m.student_id
                WHERE m.course_id=:course AND m.student_id=:student AND m.left_at IS NULL
                  AND s.active AND s.deleted_at IS NULL AND s.role='student')
            """), params):
                raise ValueError("current active student in the environment's course required")
            existing = uow.scalar(text("""
                SELECT id FROM control_plane.environment_assignments WHERE environment_id=:env
                  AND (group_id=:group OR student_id=:student) AND revoked_at IS NULL
            """), params)
            if existing:
                return existing
            assignment = uow.scalar(text("""
                INSERT INTO control_plane.environment_assignments(environment_id,course_id,group_id,student_id,assigned_by)
                VALUES (:env,:course,:group,:student,:actor) RETURNING id
            """), params)
            _audit(uow, actor_id, "environment.assign", env=environment_id, assignment_id=assignment)
            return assignment

    def revoke_assignment(self, actor_id, assignment_id):
        with self.runtime.fenced_transaction() as uow:
            assignment = uow.execute(text("""
                SELECT environment_id,course_id FROM control_plane.environment_assignments WHERE id=:id
            """), {"id": assignment_id}).first()
            if assignment is None:
                raise AuthorizationDenied()
            _managed_course(uow, actor_id, assignment.course_id)
            with _track_student_access(uow, actor_id, environment_id=assignment.environment_id):
                changed = uow.scalar(text("""
                    UPDATE control_plane.environment_assignments SET revoked_at=clock_timestamp()
                    WHERE id=:id AND revoked_at IS NULL RETURNING id
                """), {"id": assignment_id})
            if changed:
                _audit(uow, actor_id, "environment.unassign", env=assignment.environment_id,
                       assignment_id=assignment_id)
