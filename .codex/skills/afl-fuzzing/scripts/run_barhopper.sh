cd /data/local/tmp/bh
export LD_LIBRARY_PATH=/data/local/tmp/bh
export AFL_PRELOAD=/data/local/tmp/bh/libdislocator.so
export AFL_SKIP_BIN_CHECK=1 AFL_SKIP_CPUFREQ=1 AFL_NO_AFFINITY=1
export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 AFL_NO_UI=1
DUR=${1:-240}
timeout ${DUR} /data/local/tmp/afl-fuzz -n -m none -t 1500 \
   -i /data/local/tmp/bh/seeds -o /data/local/tmp/bh/out -- /data/local/tmp/bh/harness @@ \
   > /data/local/tmp/bh/afl.log 2>&1
echo "AFL-EXIT=$?"
