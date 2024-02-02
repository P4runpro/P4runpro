#!/bin/bash
PYEXE=`which python`
PYPYTH=${PYPYTH}:$SDE/install/lib/python2.7/site-packages/bf-ptf
PYPYTH=${PYPYTH}:$SDE/install/lib/python2.7/site-packages/${USER}testutils
PYPYTH=${PYPYTH}:$SDE/install/lib/python2.7/site-packages/tofinopd
PYPYTH=${PYPYTH}:$SDE/install/lib/python2.7/site-packages/tofino
PYPYTH=${PYPYTH}:$SDE/install/lib/python2.7/site-packages
PYPYTH=${PYPYTH}:$SDE/install/lib/python2.7/site-packages/tofino/bfrt_grpc
#PYPYTH=${PYPYTH}:/usr/local/python3/lib/python3.5/site-packages
PYTHONPATH=${PYPYTH} $PYEXE main.py
