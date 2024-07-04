# P4runpro

### Introduction

P4runpro enables runtime programmability for RMT switches. This prototype is implemented on an Intel Tofino switch. It is only an experimental prototype and has yet to be tested and validated on an industrial scale. This document will help the user deploy P4runpro and reproduce the result in our paper **["P4runpro: Enabling Runtime Programmability for RMT Programmable Switches"](https://doi.org/10.1145/3651890.3672230)**.

### Contents

* An example implementation of the P4runpro data plane and a code generator for customization
* P4runpro control plane cmd controller
* Example of 15 P4runpro programs
* Evaluation code for reproduction of main results in the paper

### Recommended Requirements

We only make sure our prototype runs under these requirements:

* Data plane: A Tofino-based hardware switch or a Tofino model

* Control plane:  Intel SDK for the Tofino development with **SDE 9.4.0**
* Python 2.7 for hardware running and Python 3.5 for simulation
* Python module: jinjia2, ply, z3, gurobipy and matplotlib (for result reproduction)

### Run P4runpro

##### Download

  ```bash
  git clone https://github.com/P4runpro/P4runpro.git
  cd P4runpro
  ```

##### Run Data Plane 

* Customize (**optional**)

  **Note: The steps below can be skipped if you do not want to customize P4runpro**

  * Edit the template file to customize your RPB and generate it
  
  ```bash
  vim ./template/runproblock.p4template 
  python p4codegen.py
  cp ./template/generated_runproblock.p4 ./p4src/runproblock.p4
  ```

  * Edit the config.h, p4src/header.p4, and p4src/parser.p4 to customize your parsing logic

  ```bash
  vim ./config.h
  vim ./p4src/header.p4
  vim ./p4src/parser.p4
  ```

  * Edit the initialization block to customize your traffic filtering tables
  
  ```bash
  vim ./p4src/initblock.p4
  ```

* Compile and run data plane

  ```bash
  $SDE/p4_build.sh ./p4src/p4runpro.p4 P4FLAGS="-Xp4c=--traffic-limit=98"
  $SDE/run_switchd.sh -p p4runpro
  ```

* Configure ports

  ```bash
  bfshell> ucli
  bf-sde> pm
  bf-sde.pm> port-add -/- 100g rs
  bf-sde.pm> show
  ```

##### Run Control Plane

* Open another shell

  ```bash
  cd /your/path/to/P4runpro/control_plane
  ```

* Run

  ```bash
  ./run.sh
  ```

  **Note: If running the control plane under Python2 with the error about the z3 prover, we offer another ILP solver using groubipy for the Python2 environment (the z3 prover discontinued its support for python2). This solver cannot support the memory and table entry constraints (Constraints (2) and (3) in the paper) but it is enough for the evaluation.**

  To change the solver, modify the lines 16 and 17 in ```p4runpro_main.py```

  ```bash
  vim ./p4runpro_main.py
  16 from ilp_solver import *
  17 #from smt_solver import *
  ```

  If no error occurs:

  ```bash
  Subscribe attempt #1
  Subscribe response received 0
  Binding with p4_name p4runpro
  Binding with p4_name p4runpro successful!!
  Received p4runpro on GetForwarding on client 0, device 0
  connect successfully!
  p4 program: p4runpro
  client id: 0



  ----------P4runpro controller starts!!----------

  P4runpro> 
  ```

##### Deploy/revoke/show programs

* Write your p4runpro programs or use the example programs to deploy

  ```bash
  P4runpro> deploy -f /your/path/to/P4runpro/programs/Cache.p4runpro
  ```

* Show allocated programs

  ```bash
  P4runpro> show
  ```

* Revoke a program

  ```bash
  P4runpro> revoke -p cache
  ```

### Main results reproduction

For the experimental results of ActiveRMT and FlyMon, refer [here1](https://github.com/ucsdsysnet/activermt) and [here2](https://github.com/NASA-NJU/FlyMon) to reproduce.

#### Update delay (Table 1)

* Run the data plane and control plane as mentioned above
* Evaluate the update delay of programs

  ```bash
  P4runpro> evaluate_update_delay -p /your/path/to/P4runpro/programs
  ```

#### Allocation delay, resource utilization, and program capacity (Figure 7, Figure 8, and Figure 9)

We use a simulator to simulate these three experiments, the main results of the allocation scheme in the paper are already in the directories ```/your/path/to/P4runpro/eval/data``` and ```/your/path/to/P4runpro/eval/figure```. 

How to reproduce it again:

* Enter the eval directory

  ```bash
  cd /your/path/to/P4runpro/eval
  ```

* Edit the config  (**optional)**

  **Note: this step can be skipped if you only want to reproduce the results in the paper**

  ```bash
  vim ./configs/your_config.json
  ```

* Run all the evaluations, the results are stored in the ./eval/data/configs

  ```bash
  ./run_all_evaluation.sh
  ```

  Different config file represents the different evaluation, shown as follows:

  ```shell
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
  ```

#### Overhead (Figure 10 and Table 2)

After compilation of ```/your/path/to/P4runpro/p4src/p4runpro.p4```, see the generated logs in ```$SDE/build/p4-build/p4runpro/tofino/p4runpro/pipe/logs``` or use [P4 Insight](https://www.intel.com/content/www/us/en/products/details/network-io/intelligent-fabric-processors/p4-insight.html) for overhead evaluation

#### Visualization

* Draw the figures using the results

  ```bash
  cd /your/path/to/P4runpro/eval/draw
  ./draw_all_figures.sh
  ```

  **Note: 1) For Figure 9, the embedded data in the drawing script needs to be changed based on the new data. 2) For the workload Mixed and All-Mixed, the results might be different each time due to randomness.**

  The scripts can generate the figures in the evaluation:

  ```shell
  # Figure 7(a)
  python3 draw_AllocationDelay.py  
  # Figure 7(b)
  python3 draw_Granularity_AllocationDelay.py
  # Figure 8
  python3 draw_ResourceUtilization.py                      
  # Figure 9
  python3 draw_ProgramCapacity.py
  # Figure 10
  python3 draw_ResourceOverhead.py
  # Figure 11
  python3 draw_Recirculation.py
  # Figure 12
  python3 draw_AlternativeOptimizationChoice_LineChart.py   
  # Figure 18
  python3 draw_AlternativeOptimizationChoice_HeatMap_Memory.py  
  # Figure 19
  python3 draw_AlternativeOptimizationChoice_HeatMap_Table.py 
  ```

#### Case study

**Considering user privacy protection**, we cannot provide the campus network traffic used in our paper‘s case study. 

##### Impacts on Traffic

* Playing background traffic
* Run the data plane and control plane as mentioned above
* Configure the forward table

  ```bash
  P4runpro> add_froward -ip your_ingress_port_numebr -ep your_egress_port_numebr
  ```

* Randomly deploy and revoke

  ```bash
  P4runpro> case_study_random_deploy -p /your/path/to/P4runpro/programs -c 30
  ```

* Observe the recieved traffic

##### In-network cache

* Playing background traffic
* Run the data plane and control plane as mentioned above

* Deploy the program **Cache**

  ```bash
  P4runpro> deploy -f /your/path/to/P4runpro/programs/Cache.p4runpro
  ```

* Play the groud truth traffic and analysis recieved data

##### Stateless load balancer

* Playing background traffic
* Run the data plane and control plane as mentioned above

* deploy the program **LB**

  ```bash
  P4runpro> deploy -f /your/path/to/P4runpro/programs/LoadBalancer.p4runpro
  ```

* Play the groud truth traffic and analysis recieved data  

##### Heavy hitter detector

* Playing background traffic
* Run the data plane and control plane as mentioned above

* Deploy the program **HH**

  ```bash
  P4runpro> deploy -f /your/path/to/P4runpro/programs/HeavyHitter.p4runpro
  ```

* Play the groud truth traffic and analysis recieved data 

### License

This work is licensed under a Creative Commons Attribution International 4.0 BY License.

### Cite

If you feel our paper or prototype helpful, please cite our paper as follow:

```cite
Yifan Yang, Lin He, Jiasheng Zhou, Xiaoyi Shi, Jiamin Cao, and Ying Liu. 2024. P4runpro: Enabling Runtime Programmability for RMT Programmable Switches. In ACM SIGCOMM 2024 Conference (ACM SIGCOMM ’24), August 4–8, 2024, Sydney, NSW, Australia. ACM, New York, NY, USA, 17 pages. https://doi.org/10.1145/3651890.3672230
```

### Contact

If you have any other questions, you are welcome to contact the authors:

```
The first author: Yifan Yang, Tsinghua University, yangyifan0202@gmail.com
The corresponding author: Lin He, Tsinghua University, helin1170@gmail.com
```

