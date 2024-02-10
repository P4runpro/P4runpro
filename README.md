# P4Runpro

P4runpro enables runtime programmability for RMT switches. This prototype is implemented on an Intel Tofino switch. It is only an experimental prototype and  has yet to be tested and validated on an industrial scale.

### Contents

* An example implementation of the P4runpro data plane and a code generator for customization
* P4runpro control plane cmd controller
* Example of 15 P4runpro programs
* Evaluation code for reproduction of main results in the paper

### Running P4Runpro

##### Requirement

* Control plane:  A Tofino model of Tofino-based hardware switch with bf-SDE 9.4.0+
* Python 2 or Python 3, according to the SDE version
* Python module: jinjia2, Z3, ply

##### Running Data Plane 

Note:  the first step can be skipped because there is already code that can be run under the directory ./p4src

* Customization

  * Edit the template file to customize your RPB

  * Edit the config.h, header.p4, and parser.p4 to customize your parsing logic


  ```bash
  vim ./template/p4runproblock.p4
  python p4codegen.py
  vim ./config.h
  vim ./p4src.header.p4
  vim ./p4src.parser.p4
  ```

* Compile and run data plane

  ```bash
  $SDE/p4_build.sh ./p4src/p4runpro.p4 --P4FLAGS="-Xp4c=--traffic-limit=98"
  $SDE/run_switchd.sh -p p4runpro
  ```

##### Running Control Plane

* ```bash
  python ./control_plane/p4runpro_main.py
  ```

  If no error occurs:

  ```bash
  Subscribe attempt #1
  Subscribe response received 0
  Binding with p4_name p4r2
  Binding with p4_name p4r2 successful!!
  Received p4r2 on GetForwarding on client 0, device 0
  connect successfully!
  p4 program: p4runpro
  client id: 0
  
  
  
      P4runpro controller start!!
      
  P4runpro> 
  ```

##### Deploying a program

* Write your p4runpro programs or use the example programs

  ```bash
  P4runpro> deploy -f ./prorgams/Cache.p4runpro
  ```


##### Revoke a program

```bash
P4runpro> revoke -p cache
```

### Results Reproduction

The main results of the allocation scheme in the paper are in the directory

```bash
./eval/data
./eval/figure
```

##### reproducing the results

* Edit the config (this step can be skipped if you only want to reproduce the results in the paper)

  ```bash
  vim ./eval/configs/configx.json
  ```

* Run evaluation, the results are stored in the ./eval/data/configx

  ```bash
  cd ./eval
  python allocation.py ./configs/configx.json
  ```

* Visualization

  ```bash
  cd ./draw
  python draw_xxx.py
  ```

  
