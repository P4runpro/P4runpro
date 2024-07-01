#!/bin/bash
PYEXE=`which python`
PYPYTH=${PYPYTH}:$SDE/install/lib/python2.7/site-packages/tofino
#PYPYTH=${PYPYTH}:/usr/local/python3/lib/python3.5/site-packages/tofino
PYTHONPATH=${PYPYTH} $PYEXE p4runpro_main.py