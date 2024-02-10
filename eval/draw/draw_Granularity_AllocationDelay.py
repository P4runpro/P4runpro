import os
import json
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
from matplotlib.ticker import MultipleLocator
import matplotlib
matplotlib.use('Agg')

epoch_time = 500

def MA(array, windowsize):
    end = np.convolve(array, np.ones(windowsize), "valid") / windowsize
    front = []
    for i in range(windowsize-1):
        front.append(np.sum(array[0:i+1])/(i+1))
    print(front)
    return np.concatenate((np.array(front), end), axis=0)

# Store the average allocation_time for each epoch of each scheme
average_allocation_times_per_scheme = []

# Iterate over each scheme
for scheme_id in range(8, 12):
    print(scheme_id)
    scheme_directory = "../data/config2/scheme{}/".format(scheme_id)

    # Store allocation_time for each epoch of the current scheme
    allocation_times_per_scheme = {epoch: [] for epoch in range(epoch_time)}

    # Iterate over each repeated experiment
    for experiment_id in range(10):
        experiment_directory = os.path.join(scheme_directory, str(experiment_id))

        # Check if the folder exists
        if os.path.exists(experiment_directory):
            # Iterate over each epoch
            for epoch in range(epoch_time):
                file_path = os.path.join(experiment_directory, "output.json")
                # Check if the file exists
                if os.path.exists(file_path):
                    with open(file_path, 'r') as file:
                        data = json.load(file)

                        # Get the allocation_time for the current epoch
                        if str(epoch) in data:
                            allocation_time = data[str(epoch)]['allocation_time']
                            allocation_times_per_scheme[epoch].append(allocation_time)

    # Calculate the average allocation_time for each epoch and store it
    average_allocation_times_per_epoch = [np.mean(values) for values in allocation_times_per_scheme.values()]
    average_allocation_times_per_scheme.append(average_allocation_times_per_epoch)

# Plot the line graph
fig, ax = plt.subplots(figsize=(12, 8))

scheme_labels = ['128B-P4runpro', '256B-P4runpro', '512B-P4runpro', '1024B-P4runpro']

colors = ['tab:blue', 'tab:orange', 'tab:green', 'tab:red']

for i in range(4):
    ax.plot(range(epoch_time), MA(average_allocation_times_per_scheme[i],11), label=scheme_labels[i], linestyle='solid', color=colors[i],linewidth=4.0)

# Set the y-axis to logarithmic scale
ax.set_yscale('log')

# Set the range for logarithmic scale
ax.set_ylim([100, 10000])

# Use LogLocator to set logarithmic scale
ax.yaxis.set_major_locator(ticker.LogLocator(numticks=5))

# Add horizontal and vertical grid lines
ax.grid(axis='both', linestyle='--', color='gray', alpha=0.7)

ax.set_xlabel('Epoch', fontsize=40, fontweight='bold')
ax.set_ylabel('Allocation Delay (ms)', fontsize=40, fontweight='bold')
ax.legend(loc='upper left', ncol=2, fontsize=24)

# Set font size for numbers on the axes
ax.tick_params(axis='both', which='both', labelsize=40)

ax.set_xlim(left=0,right = 500)

plt.savefig('../figure/draw_Granularity_AllocationDelay_mixed.png',bbox_inches='tight')
plt.savefig('../figure/draw_Granularity_AllocationDelay_mixed.svg',bbox_inches='tight')
