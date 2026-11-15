"""Deterministic bounded-capacity tests; no production resources."""
from datetime import datetime, timedelta, timezone
import json
import subprocess
import sys
import threading
import unittest

from control_plane.plugins.capacity import CapacityRejected, CapacitySettings, CapacitySupervisor
from control_plane.plugins.sdk import Deadline, ExecutionPolicy, ExecutionResult, PreparedCall, finite_json
from tests_control_plane.pg_harness import ROOT


def expires(seconds=3):
    return datetime.now(timezone.utc) + timedelta(seconds=seconds)


class SdkTests(unittest.TestCase):
    def test_prepared_roundtrip_and_policy_cannot_invent_guarantee(self):
        call = PreparedCall("run", {"n": 1}, target_ref={"opaque": "target"})
        self.assertEqual(PreparedCall.from_dict(call.to_dict()), call)
        with self.assertRaises(ValueError):
            ExecutionPolicy(effect="read_only").validate_against(ExecutionPolicy())
        with self.assertRaises(ValueError):
            ExecutionPolicy(idempotency="keyed").validate_against(ExecutionPolicy())
        ExecutionPolicy().validate_against(ExecutionPolicy(effect="read_only", idempotency="keyed"))

    def test_json_rejects_secret_objects_cycles_limits_nan(self):
        cycle = {}
        cycle['cycle'] = cycle
        for value in (cycle, {"n": float('nan')}, {"n": object()}, {"a": list(range(1001))}, {"a": "x" * 1048577}):
            with self.assertRaises(ValueError):
                finite_json(value)

    def test_only_success_has_formal_output(self):
        with self.assertRaises(ValueError):
            ExecutionResult("unknown", output={"not": "success"})
        self.assertEqual(ExecutionResult.from_dict(ExecutionResult("succeeded", output=[]).to_dict()).output, [])

    def test_deadline_never_refreshes_and_requires_aware_time(self):
        deadline = Deadline.after(1)
        before = deadline.remaining()
        self.assertLessEqual(deadline.remaining(), before)
        with self.assertRaises(ValueError):
            Deadline.from_at(datetime.now())
        for seconds in (0, -1, float('inf'), float('nan'), True):
            with self.assertRaises(ValueError):
                Deadline.after(seconds)


class CapacityTests(unittest.TestCase):
    def make(self, **kwargs):
        defaults = dict(ordinary_workers=1, control_workers=1, session_workers=1,
                        queue_limit=1, instance_limit=1, shutdown_grace_seconds=0.2)
        defaults.update(kwargs)
        pool = CapacitySupervisor(CapacitySettings(**defaults))
        self.addCleanup(pool.stop, 0.2)
        return pool

    def blocking(self, pool, *, instance="a", deadline=None, lane="ordinary"):
        entered, release = threading.Event(), threading.Event()
        self.addCleanup(release.set)
        def run():
            entered.set()
            release.wait(5)
            return "returned"
        handle = pool.submit(instance, run, deadline_at=deadline or expires(), lane=lane)
        self.assertTrue(entered.wait(2))
        return handle, release

    def test_requires_explicit_start(self):
        pool = self.make()
        with self.assertRaises(CapacityRejected):
            pool.submit('a', lambda: 1, deadline_at=expires())
        pool.start()
        self.assertEqual(pool.submit('a', lambda: 1, deadline_at=expires()).result(2), 1)

    def test_instance_cannot_consume_other_instance_reservation(self):
        pool = self.make(ordinary_workers=2)
        pool.start()
        handle, release = self.blocking(pool)
        with self.assertRaises(CapacityRejected):
            pool.submit('a', lambda: 1, deadline_at=expires())
        self.assertEqual(pool.submit('b', lambda: 2, deadline_at=expires()).result(2), 2)
        self.assertFalse(handle.done())
        release.set()
        self.assertEqual(handle.result(2), 'returned')

    def test_control_and_session_lanes_independent_of_ordinary_hang(self):
        pool = self.make()
        pool.start()
        handle, release = self.blocking(pool)
        self.assertEqual(pool.submit('a', lambda: 3, deadline_at=expires(), lane='control').result(2), 3)
        self.assertEqual(pool.submit('a', lambda: 4, deadline_at=expires(), lane='session').result(2), 4)
        self.assertFalse(handle.done())
        release.set()
        handle.result(2)

    def test_timeout_does_not_return_real_slot(self):
        pool = self.make()
        pool.start()
        # The callable waits on a separate event even after its finite deadline.
        handle, release = self.blocking(pool, deadline=expires(0.1))
        self.assertFalse(handle._event.wait(0.15))
        self.assertTrue(handle.expired)
        with self.assertRaises(TimeoutError):
            handle.result(0)
        with self.assertRaises(CapacityRejected):
            pool.submit('a', lambda: 1, deadline_at=expires())
        status = pool.snapshot()
        self.assertEqual(status['lanes']['ordinary']['overdue'], 1)
        self.assertTrue(status['degraded'])
        self.assertTrue(status['manual_restart_required'])
        release.set()
        handle.result(2)
        self.assertEqual(pool.snapshot()['retained_calls'], 0)
        self.assertEqual(pool.submit('a', lambda: 1, deadline_at=expires()).result(2), 1)

    def test_bounded_queue_and_no_extra_threads(self):
        pool = self.make(instance_limit=2)
        pool.start()
        handle, release = self.blocking(pool)
        queued = pool.submit('b', lambda: 2, deadline_at=expires())
        with self.assertRaises(CapacityRejected):
            pool.submit('c', lambda: 3, deadline_at=expires())
        self.assertEqual(len(pool._threads), 3)
        self.assertEqual(pool.snapshot()['lanes']['ordinary']['queued'], 1)
        release.set()
        handle.result(2)
        self.assertEqual(queued.result(2), 2)

    def test_stop_cancels_only_provably_unstarted_work(self):
        pool = self.make(instance_limit=2)
        pool.start()
        handle, release = self.blocking(pool)
        touched = threading.Event()
        queued = pool.submit('b', touched.set, deadline_at=expires())
        status = pool.stop(0)
        self.assertEqual(status['retained_calls'], 1)
        self.assertFalse(handle.done())
        self.assertFalse(touched.is_set())
        with self.assertRaises(CapacityRejected):
            queued.result(0)
        with self.assertRaises(CapacityRejected):
            pool.check_admission()
        with self.assertRaises(RuntimeError):
            pool.start()
        release.set()
        handle.result(2)

    def test_exception_returns_slot_only_after_frame_returns(self):
        pool = self.make()
        pool.start()
        def fail():
            raise ValueError('safe-test-failure')
        handle = pool.submit('a', fail, deadline_at=expires())
        with self.assertRaises(ValueError):
            handle.result(2)
        self.assertEqual(pool.snapshot()['retained_calls'], 0)
        self.assertEqual(pool.submit('a', lambda: True, deadline_at=expires()).result(2), True)

    def test_invalid_capacity_and_past_deadline_rejected(self):
        for kwargs in ({'ordinary_workers': 0}, {'queue_limit': 0}, {'instance_limit': 5000},
                       {'shutdown_grace_seconds': float('nan')}, {'control_workers': True}):
            with self.assertRaises(ValueError):
                CapacitySettings(**kwargs)
        pool = self.make()
        pool.start()
        with self.assertRaises(Exception):
            pool.submit('a', lambda: None, deadline_at=expires(-1))

    def test_permanent_call_isolated_test_process_can_be_terminated(self):
        code = '''
from control_plane.plugins.capacity import CapacitySupervisor,CapacitySettings,CapacityRejected
from datetime import datetime,timedelta,timezone
import threading,json
pool=CapacitySupervisor(CapacitySettings(ordinary_workers=1,control_workers=1,session_workers=1,queue_limit=1,instance_limit=1))
pool.start()
entered=threading.Event()
def stuck():
 entered.set()
 threading.Event().wait()
h=pool.submit('a',stuck,deadline_at=datetime.now(timezone.utc)+timedelta(seconds=.1))
assert entered.wait(2)
assert not h._event.wait(.15)
s=pool.stop(0)
assert s['retained_calls']==1 and not h.done() and s['degraded']
print('PERMANENT_SLOT_RETAINED',flush=True)
'''
        result = subprocess.run([sys.executable, '-B', '-c', code], cwd=ROOT,
                                capture_output=True, text=True, timeout=8)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('PERMANENT_SLOT_RETAINED', result.stdout)
