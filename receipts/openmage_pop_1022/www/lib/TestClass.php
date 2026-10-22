<?php
/**
 * LAB-ONLY class for the OpenMage session-injection receipt.
 * Not part of OpenMage. It exists solely to show that the *application's*
 * session_start() autoloads a class named in the session file and runs its
 * magic methods. Markers live outside the docroot.
 */
class TestClass
{
    public function __wakeup()
    {
        @file_put_contents('/tmp/opencode/research/openmage_pop_20261022T021222Z/markers/testclass_wakeup.log',
            date('c') . ' wakeup pid=' . getmypid() . ' sapi=' . PHP_SAPI . "\n", FILE_APPEND);
        @touch('/tmp/opencode/research/openmage_pop_20261022T021222Z/MARK_WAKEUP');
    }

    public function __destruct()
    {
        @file_put_contents('/tmp/opencode/research/openmage_pop_20261022T021222Z/markers/testclass_destruct.log',
            date('c') . ' destruct pid=' . getmypid() . ' sapi=' . PHP_SAPI . "\n", FILE_APPEND);
        @touch('/tmp/opencode/research/openmage_pop_20261022T021222Z/MARK_DESTRUCT');
    }
}
