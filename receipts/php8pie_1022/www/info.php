<?php
echo "PID=", getmypid(), "\n";
echo "serializer=", ini_get('session.serialize_handler'), " save_path=", ini_get('session.save_path'), "\n";
echo "up=", ini_get('session.upload_progress.enabled'), " freq=", ini_get('session.upload_progress.freq'), " min=", ini_get('session.upload_progress.min_freq'), " cleanup=", ini_get('session.upload_progress.cleanup'), " prefix=[", ini_get('session.upload_progress.prefix'), "]\n";
echo "maps=", file_get_contents('/proc/self/maps') ? 'no' : 'no', "\n";
