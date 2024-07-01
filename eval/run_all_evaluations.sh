#!/bin/bash
# Evaluation for Figure 7(a)
python3 allocation.py ./configs/config1.json
# Evaluation for Figure 7(b)
python3 allocation.py ./configs/config2.json
# Evaluation for Figure 8
python3 allocation.py ./configs/config10.json
# Evaluation for the Baseline, 2048B, and 4096B with the workload Cache, LB, and HH in Figure 9
python3 allocation.py ./configs/config12.json
# Evaluation for the 16Cases, 256 Cases with the workload Cache, LB, and HH in Figure 9
python3 allocation.py ./configs/config13.json
# Evaluation for the workload All-mixed in Figure 9
python3 allocation.py ./configs/config14.json
# Evaluation for Figure 18 and Figure 19
# Evaluation for Figure 12(a)
python3 allocation.py ./configs/config4.json
# Evaluation for Figure 12(b)
python3 allocation.py ./configs/config5.json
# Evaluation for Figure 12(c)
python3 allocation.py ./configs/config3.json
# Evaluation for Figure 12(d)
python3 allocation.py ./configs/config7.json


