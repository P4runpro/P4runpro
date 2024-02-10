import os
import json
import numpy as np
import matplotlib.pyplot as plt
import matplotlib
import itertools
from itertools import chain
matplotlib.use('Agg')

# Plot a line chart
fig, ax1 = plt.subplots(figsize=(12, 8))

throughput1 = [100, 89, 60, 40.5, 27.3, 18.7, 15.6]
throughput2 = [100, 95, 68, 44.4, 33.3, 26.7, 22.2]
throughput3 = [100, 98, 75, 49.6, 37, 29.7, 24.7]
throughput4 = [100, 99, 76, 50.1, 37.5, 30, 25]

RTT1 = [i/1000 for i in [0, 4, 9, 163, 230, 425, 440]]
RTT2 = [i/1000 for i in [15, 17, 333, 398, 439, 549, 555]]
RTT3 = [i/1000 for i in [131, 419, 437, 558, 562, 809, 1034]]
RTT4 = [i/1000 for i in [234, 488, 583, 768, 818, 908, 1698]]

color = 'tab:red'
ax1.set_xlabel('Iteration Number', fontsize=40, fontweight='bold')
ax1.set_ylabel('Throughput (Gbps)', fontsize=40, fontweight='bold')
ax1.set_xticks([0, 1, 2, 3, 4, 5, 6])

ax1.plot(range(0, 7), throughput1, label='128B-TP', linestyle='solid', color='blue',linewidth=4.0)
ax1.plot(range(0, 7), throughput2, label='256B-TP', linestyle='solid', color='orange',linewidth=4.0)
ax1.plot(range(0, 7), throughput3, label='512B-TP', linestyle='solid', color='green',linewidth=4.0)
ax1.plot(range(0, 7), throughput4, label='1500B-TP', linestyle='solid', color='red',linewidth=4.0)

ax1.tick_params(axis='y')

ax1.set_xlim(left=0,right=6)
# Set the bottom of the y-axis to '0'
ax1.set_ylim(bottom=0,top=100)

ax2 = ax1.twinx()  # instantiate a second axes that shares the same x-axis

color = 'tab:blue'
ax2.set_ylim(bottom=0,top=2.0)
ax2.set_ylabel('Normalized RTT (ms)', fontsize=40, fontweight='bold')  # we already handled the x-label with ax1

ax2.plot(range(0, 7), RTT1, label='128B-RTT', linestyle='dashed', color='blue',linewidth=4.0)
ax2.plot(range(0, 7), RTT2, label='256B-RTT', linestyle='dashed', color='orange',linewidth=4.0)
ax2.plot(range(0, 7), RTT3, label='512B-RTT', linestyle='dashed', color='green',linewidth=4.0)
ax2.plot(range(0, 7), RTT4, label='1500B-RTT', linestyle='dashed', color='red',linewidth=4.0)

ax2.tick_params(axis='y')

# Set the font size of the axis labels
ax1.tick_params(axis='both', which='both', labelsize=40)
ax2.tick_params(axis='both', which='both', labelsize=40)


# Add horizontal and vertical grid lines
ax1.grid(axis='both', linestyle='--', color='gray', alpha=0.7)
ax2.grid(axis='both', linestyle='--', color='gray', alpha=0.7)


# Create a new legend, merging the legends of ax1 and ax2
legend_handles = []
legend_labels = []

for ax in [ax1, ax2]:
    handles, labels = ax.get_legend_handles_labels()
    legend_handles.extend(handles)
    legend_labels.extend(labels)

# Draw a new legend in one of the subplots (here ax1)
ax1.legend(legend_handles, legend_labels, fontsize=24,ncol=2, loc= 'upper right')

plt.savefig('../figure/Recirculation.png',bbox_inches='tight')
plt.savefig('../figure/Recirculation.svg',bbox_inches='tight')
