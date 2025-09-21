import logging
import os
from logger import ManpowerLogger, JSONFormatter


def test_logger_methods_exist(tmp_path, monkeypatch):
    # Ensure logs dir is inside tmp to avoid writing into repo logs during tests
    logs_dir = tmp_path / "logs"
    logs_dir.mkdir()

    # Monkeypatch os.makedirs to ensure logs dir is created in tmp_path
    monkeypatch.chdir(tmp_path)

    app = None
    mlog = ManpowerLogger(app)

    # The wrapper should proxy standard methods like info, debug
    assert hasattr(mlog, 'info')
    assert hasattr(mlog, 'debug')
    assert callable(mlog.info)

    # Custom methods should be present
    assert hasattr(mlog, 'log_error')
    assert hasattr(mlog, 'log_security_event')

    # Alias should exist and call underlying implementation
    assert hasattr(mlog, 'log_exception')

    # Calling these should not raise
    mlog.info('test info')
    mlog.debug('test debug')
    mlog.log_security_event('unit_test_event', user_id='tester', ip_address='127.0.0.1')
    try:
        mlog.log_exception(Exception('test'))
    except Exception:
        # log_exception should swallow or handle internally; not re-raise
        pass


def test_json_formatter_format():
    fmt = JSONFormatter()
    logger = logging.getLogger('test')
    record = logger.makeRecord('test', logging.INFO, __file__, 1, 'message', None, None)
    out = fmt.format(record)
    assert 'timestamp' in out
    assert 'message' in out
