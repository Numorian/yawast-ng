pipenv run memray run -o flamegraph.bin ./bin/yawast-ng scan --nossl https://adamcaudill.com
pipenv run memray flamegraph --temporal flamegraph.bin
rm flamegraph.bin
