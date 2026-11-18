"""Explicit composition of trusted plugins, P3 business services, and execution.

A deployment configuration enables loading trusted packages, never Python paths
from the database. Without it the P0/P1 database/coordinator-only mode remains
available, but is not represented as a functioning business execution service.
"""
from __future__ import annotations

from dataclasses import asdict
from pathlib import Path

from .config import ConfigurationError
from .plugins.capacity import CapacitySettings, CapacitySupervisor


def load_deployment(path):
    # Lazy parsing: no filesystem access on import or RuntimeSettings creation.
    from .plugins.registry import safe_yaml
    try:
        location = Path(path).resolve()
        data = safe_yaml(location)
        if not isinstance(data, dict) or set(data) != {'schema_version', 'plugin_directory', 'required', 'optional', 'capacity', 'max_pending_jobs'}:
            raise ValueError()
        if data['schema_version'] != 1:
            raise ValueError()
        for kind in ('required', 'optional'):
            if not isinstance(data[kind], list) or any(not isinstance(key, str) or not key for key in data[kind]) or len(data[kind]) > 1000:
                raise ValueError()
            if len(set(data[kind])) != len(data[kind]):
                raise ValueError()
        if set(data['required']) & set(data['optional']):
            raise ValueError()
        if not isinstance(data['plugin_directory'], str) or not data['plugin_directory']:
            raise ValueError()
        # Explicit deployment values, not accidental infinity or executor defaults.
        if not isinstance(data['capacity'], dict) or set(data['capacity']) != set(asdict(CapacitySettings())):
            raise ValueError()
        if isinstance(data['max_pending_jobs'], bool) or not isinstance(data['max_pending_jobs'], int) or not 1 <= data['max_pending_jobs'] <= 100000:
            raise ValueError()
        limits = CapacitySettings(**data['capacity'])
        directory = (location.parent / data['plugin_directory']).resolve()
        return data, directory, limits
    except Exception:
        raise ConfigurationError('runtime configuration is invalid') from None


class PluginServices:
    def __init__(self, runtime, *, driver_factory=None, session_factory=None):
        self.runtime = runtime
        self.driver_factory, self.session_factory = driver_factory, session_factory
        self.capacity = None
        self.registry = None
        self.contexts = None
        self.storage = None
        self.secrets = None
        self.configuration = None
        self.driver = None
        self.sessions = None
        self.admission = None
        self.business = self.identity = self.templates = self.credentials = self.access = None
        self._state = 'stopped'

    def start(self):
        if self._state != 'stopped':
            raise RuntimeError('plugin services are not stopped')
        path = self.runtime.settings.deployment_path
        if path is None:
            # No secret key is invented just to make a health check pass.
            self._state = 'foundation_only'
            return
        from .plugins.registry import PluginRegistry
        from .plugins.storage import StorageService
        from .plugins.configuration import ConfigurationService
        from .plugins.secrets import SecretService
        from .plugins.context import ContextBuilder
        data, directory, limits = load_deployment(path)
        self.registry = PluginRegistry().load(directory, required=data['required'], optional=data['optional'])
        self.capacity = CapacitySupervisor(limits)
        try:
            self.secrets = SecretService.from_env(self.runtime._engine, self.runtime)
        except ValueError:
            raise ConfigurationError('runtime encryption keyring is unavailable') from None
        self.storage = StorageService(self.runtime._engine, self.runtime, safe_json=self.secrets.safe_json)
        self.configuration = ConfigurationService(self.runtime._engine, self.runtime, self.registry,
                                                  safe_json=self.secrets.safe_json)
        self.contexts = ContextBuilder(self.runtime._engine, self.runtime, self.registry, self.secrets)
        self.capacity.start()
        from .admission import AdmissionController
        self.admission = AdmissionController(self.runtime, self.capacity, max_pending_jobs=data['max_pending_jobs'])
        from .access import AccessService
        from .business import BusinessService, authorize_job
        from .credentials import CredentialService
        from .execution.driver import ExecutionDriver
        from .execution.repository import Repository
        from .identity import IdentityService
        from .selectors import SelectorService
        from .templates import TemplateService
        from .workflows import TemplateWorkflow

        self.identity = IdentityService(self.runtime)
        self.access = AccessService(self.runtime, self.registry)
        self.templates = TemplateService(self.runtime, registry=self.registry, safe_json=self.secrets.safe_json)
        selectors = SelectorService(self.runtime, self.configuration, self.storage, self.registry, self.capacity)
        self.business = BusinessService(self, selectors, max_pending_jobs=data['max_pending_jobs'])
        self.credentials = CredentialService(self.runtime, self.secrets, run_action=self.business.run_action,
                                             registry=self.registry)
        self._state = 'running'
        if self.driver_factory is not None:
            self.driver = self.driver_factory(self)
        else:
            # Unavailable optional packages only block dependent workflows.
            workflow = TemplateWorkflow()
            self.driver = ExecutionDriver(Repository(self.runtime, authorize_job=authorize_job), self.capacity,
                                         self.registry, self.contexts, planner=workflow, projector=workflow,
                                         applicator=workflow)
        if self.driver is not None:
            self.driver.start()
        if self.session_factory is not None:
            from .plugins.sessions import SessionService
            self.sessions = self.session_factory(self)
            if isinstance(self.sessions, SessionService):
                self.sessions.authorizer = self.credentials.session_authorizer
            self.sessions.start()

    def tick(self):
        if self._state != 'running':
            return
        if self.driver is not None:
            self.driver.tick()
        if self.sessions is not None:
            self.sessions.poll()
        self.credentials.poll_revocations()

    def health(self):
        capacity = self.capacity.snapshot() if self.capacity else None
        unavailable = dict(self.registry.unavailable) if self.registry else {}
        return {'mode': self._state, 'execution_enabled': self.driver is not None,
                'sessions_enabled': self.sessions is not None, 'optional_plugins': unavailable,
                'capacity': capacity, 'degraded': bool(unavailable) or bool(capacity and capacity['degraded'])}

    def stop(self):
        # The runtime revokes coordination before waiting here. Unsaved call
        # completions remain unknown for recovery; shutdown cannot guarantee the
        # termination of uncooperative plugins or remote commands.
        self._state = 'stopping'
        try:
            if self.driver is not None:
                self.driver.stop()
            if self.sessions is not None:
                self.sessions.stop()
        finally:
            if self.capacity is not None:
                self.capacity.stop()
            self._state = 'stopped'
