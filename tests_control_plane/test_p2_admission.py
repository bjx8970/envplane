"""P2 admission has bounded DB backlog and no duplicate quota side effects."""
from uuid import uuid4
import unittest

from sqlalchemy import text

from control_plane.admission import AdmissionController
from control_plane.config import RuntimeSettings
from control_plane.persistence import RequestConflict, admit_job
from control_plane.plugins.capacity import CapacityRejected
from control_plane.plugins.sdk import AuthorizationDenied
from control_plane.runtime import ControlPlaneRuntime
from tests_control_plane.p1_harness import runtime_database
from tests_control_plane.pg_harness import engine_for
from tests_control_plane.test_p1_schema import graph


class FakeCapacity:
    accepting = True
    def check_admission(self, *args):
        if not self.accepting:
            raise CapacityRejected()


class AdmissionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.admin, cls.url = cls.enterClassContext(runtime_database())
        cls.engine = engine_for(cls.admin)
        cls.addClassCleanup(cls.engine.dispose)

    def setUp(self):
        # Each method owns an independent DB scope; queued rows from other tests
        # intentionally count toward the global durable backlog bound.
        self.runtime = ControlPlaneRuntime(RuntimeSettings.from_env({'CONTROL_PLANE_DATABASE_URL': self.url}))
        self.runtime.start()
        self.addCleanup(self.runtime.stop)
        with self.engine.begin() as connection:
            self.actor, _, _, self.env, self.group = graph(connection)
        self.request = dict(actor_id=self.actor, request_key=uuid4().hex, request_digest='same-request',
            environment_id=self.env, execution_group_id=self.group, logical_invocation_id=uuid4(),
            kind='create', input={}, execution_snapshot={})
        self.calls = []
        outer = self
        class Policy:
            def authorize_and_reserve(self, uow, request):
                outer.calls.append(request['request_key'])
                # Fake one quota-like effect inside the caller transaction.
                uow.execute(text("INSERT INTO control_plane.audit_events(actor_id,action,result) VALUES (:actor,'fake.admission','reserved')"), {'actor': request['actor_id']})
                return admit_job(uow, **request)[0]
        self.capacity = FakeCapacity()
        self.policy = Policy()

    def controller(self, **kwargs):
        options = dict(max_pending_jobs=100000, authorize=lambda uow, request: True, policy=self.policy)
        options.update(kwargs)
        return AdmissionController(self.runtime, self.capacity, **options)

    def test_default_authorizer_denies_without_calling_policy(self):
        controller = AdmissionController(self.runtime, self.capacity, max_pending_jobs=10, policy=self.policy)
        with self.assertRaises(AuthorizationDenied):
            controller.submit(self.request)
        self.assertEqual(self.calls, [])

    def test_replay_returns_original_even_if_capacity_now_full(self):
        controller = self.controller()
        job, replay = controller.submit(self.request)
        self.assertFalse(replay)
        self.capacity.accepting = False
        self.assertEqual(controller.submit(self.request), (job, True))
        self.assertEqual(len(self.calls), 1)
        with self.engine.connect() as c:
            self.assertEqual(c.scalar(text("SELECT count(*) FROM control_plane.audit_events WHERE actor_id=:actor AND action='fake.admission'"), {'actor': self.actor}), 1)
        with self.assertRaises(RequestConflict):
            controller.submit({**self.request, 'request_digest': 'different'})

    def test_replay_rechecks_current_authorization(self):
        controller = self.controller()
        controller.submit(self.request)
        controller.authorize = lambda *_: False
        with self.assertRaises(AuthorizationDenied):
            controller.submit(self.request)
        self.assertEqual(len(self.calls), 1)

    def test_capacity_rejection_prevents_any_quota_write(self):
        self.capacity.accepting = False
        with self.assertRaises(CapacityRejected):
            self.controller().submit(self.request)
        self.assertEqual(self.calls, [])

    def test_durable_queue_bound_prevents_new_request(self):
        self.controller().submit(self.request)
        # There is now at least one pending row, independently of method order.
        with self.assertRaises(CapacityRejected):
            self.controller(max_pending_jobs=1).submit({**self.request, 'request_key': uuid4().hex})
        self.assertEqual(len(self.calls), 1)

    def test_post_write_capacity_failure_rolls_back_whole_request(self):
        capacity = self.capacity
        original = self.policy.authorize_and_reserve
        def reserve(uow, request):
            value = original(uow, request)
            capacity.accepting = False
            return value
        self.policy.authorize_and_reserve = reserve
        with self.assertRaises(CapacityRejected):
            self.controller().submit(self.request)
        with self.engine.connect() as c:
            self.assertEqual(c.scalar(text('SELECT count(*) FROM control_plane.jobs WHERE actor_id=:actor'), {'actor': self.actor}), 0)
            self.assertEqual(c.scalar(text("SELECT count(*) FROM control_plane.audit_events WHERE actor_id=:actor AND action='fake.admission'"), {'actor': self.actor}), 0)
