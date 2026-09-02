cd /data/local/tmp
export ASAN_OPTIONS=abort_on_error=1:symbolize=0:detect_leaks=0
export AFL_SKIP_BIN_CHECK=1
export AFL_SKIP_CPUFREQ=1
export AFL_NO_AFFINITY=1
export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
export AFL_NO_UI=1
timeout 70 ./afl-fuzz -n -m none -t 2000 -i fz/seeds -o fz/out -- ./demo_parse @@
echo "AFL-EXIT=$?"
