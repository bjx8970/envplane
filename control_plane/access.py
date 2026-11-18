"""Resolve declared environment and resource session entries for P5 transports."""
from sqlalchemy import text

from .business import instance_binding
from .credentials import confirmed_session_ref_in
from .identity import active_role, can_access_environment
from .plugins.sdk import AuthorizationDenied
from .templates import load_version, resolve_access


def resolve_session_entry_in(uow, registry, actor_id, environment_id, entry_key, resource_id=None, *, manage=False):
    if not can_access_environment(uow, actor_id, environment_id, manage=manage):
        raise AuthorizationDenied()
    env = uow.execute(text("""
        SELECT id,name,template_version_id,parameters,create_results FROM control_plane.environments
        WHERE id=:env AND lifecycle='ready' AND deleted_at IS NULL FOR SHARE
    """), {'env': environment_id}).first()
    if env is None:
        raise AuthorizationDenied()
    context = {'environment': {'id': str(env.id), 'name': env.name, 'create_results': env.create_results},
               'params': env.parameters,
               'steps': {key: {'output': output} for key, output in env.create_results.items()}}
    if resource_id is None:
        access = load_version(uow, env.template_version_id, for_create=False)['access']
    else:
        row = uow.execute(text("""
            SELECT id,name,type_label,data,display,target_ref,resource_slot,item_key,access_snapshot
              FROM control_plane.experiment_resources
            WHERE id=:resource AND environment_id=:env
        """), {'resource': resource_id, 'env': env.id}).first()
        if row is None:
            raise AuthorizationDenied()
        context['resource'] = {'id': str(row.id), 'name': row.name, 'type_label': row.type_label,
                               'data': row.data, 'target_ref': row.target_ref, 'display': row.display,
                               'resource_slot': row.resource_slot, 'item_key': row.item_key}
        access = row.access_snapshot
    # The same binding supplies both the checked capability and its concrete instance.
    entry = access.get(entry_key)
    role = active_role(uow, actor_id)
    if not entry or role not in entry['roles']:
        raise AuthorizationDenied()
    identity, plugin_key = instance_binding(uow, entry['plugin_instance'])
    plugins = {entry['plugin_instance']: registry.get(plugin_key)}
    resolved = resolve_access(access, entry_key, context, role, plugins.__getitem__)
    credential = confirmed_session_ref_in(uow, env.id, resolved['credential_ref'])
    return {**resolved, 'plugin_instance_id': identity, 'credential_ref': credential}


class AccessService:
    def __init__(self, runtime, registry):
        self.runtime, self.registry = runtime, registry

    def resolve(self, actor_id, environment_id, entry_key, *, resource_id=None):
        with self.runtime.fenced_transaction() as uow:
            return resolve_session_entry_in(uow, self.registry, actor_id, environment_id, entry_key, resource_id)
