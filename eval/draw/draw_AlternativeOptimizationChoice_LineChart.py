import os
import json
import numpy as np
import matplotlib.pyplot as plt
import matplotlib
matplotlib.use('Agg')


def MA(array, windowsize):
    end = np.convolve(array, np.ones(windowsize), "valid") / windowsize
    front = []
    for i in range(windowsize-1):
        front.append(np.sum(array[0:i+1])/i)
    print(front)
    return np.concatenate((np.array(front), end), axis=0)

# Specify the directory path
directory = "../data/config5/scheme0/"

# Store the maximum key for each file
max_keys_per_file = []

max_key = 0
max_repeat = 0
for i in range(10):
    file_path = os.path.join(directory, str(i), "output.json")
    
    # Check if the file exists
    if os.path.exists(file_path):
        with open(file_path, 'r') as file:
            data = json.load(file)
            # Get the maximum key for the current file and add it to the list
            key = max(map(int, data.keys()), default=0)
            if(key > max_key):
                max_key = key
                max_repeat = i

# Store the average value for each epoch
average_table_entry_utilization = []
average_memory_utilization = []
average_allocation_time = []

# Traverse each epoch
for epoch in range(1, max_key + 1):  # Starting from 1 because epoch starts from 1
    print(epoch)
    # Store the values for the current epoch
    table_entry_utilization_values = []
    memory_utilization_values = []
    allocation_time_values = []

    # Traverse each file
    file_path = os.path.join(directory, str(max_repeat), "output.json")

    # Check if the file exists
    if os.path.exists(file_path):
        with open(file_path, 'r') as file:
            data = json.load(file)

            # Get the data for the current epoch
            if str(epoch) in data:
                table_entry_utilization_values.append(data[str(epoch)]['table_entry_utilization'])
                memory_utilization_values.append(data[str(epoch)]['memory_utilizaiton'])
                allocation_time_values.append(data[str(epoch)]['allocation_time'])

    # Calculate the average value for each epoch
    average_table_entry_utilization.append(np.mean(table_entry_utilization_values))
    average_memory_utilization.append(np.mean(memory_utilization_values))
    average_allocation_time.append(np.mean(allocation_time_values))

# Plot the line chart
fig, ax1 = plt.subplots(figsize=(12, 8))

color = 'tab:red'
ax1.set_xlabel('Epoch', fontsize=40, fontweight='bold')
ax1.set_ylabel('Utilization', color=color, fontsize=40, fontweight='bold')
ax1.plot(range(1, max_key + 1), average_table_entry_utilization, label='Entry Utilization', color=color,linewidth=4.0)
ax1.plot(range(1, max_key + 1), average_memory_utilization, label='Memory Utilization', linestyle='dashed', color=color,linewidth=4.0)
ax1.tick_params(axis='y', labelcolor=color)

ax2 = ax1.twinx()  # instantiate a second axes that shares the same x-axis

# Set the y-axis to logarithmic scale
ax2.set_yscale('log')

# Set the range for logarithmic scale
ax2.set_ylim([1, 10000])

color = 'tab:blue'
ax2.set_ylabel('Allocation Delay (ms)', color=color, fontsize=40, fontweight='bold')  # we already handled the x-label with ax1
ax2.plot(range(1, max_key + 1), MA(average_allocation_time,11), label='Allocation Time', color=color,linewidth=4.0)
ax2.tick_params(axis='y', labelcolor=color)

# Set font size for numbers on the axes
ax1.tick_params(axis='both', which='both', labelsize=40)
ax2.tick_params(axis='both', which='both', labelsize=40)

# Add horizontal and vertical grid lines
ax1.grid(axis='both', linestyle='--', color='gray', alpha=0.7)
ax2.grid(axis='both', linestyle='--', color='gray', alpha=0.7)

ax1.set_xlim(left=0,right=max_key)
# Set the bottom of the y-axis '0' to the bottom
ax1.set_ylim(bottom=0,top=1)


# Create a new legend, combining legends from ax1 and ax2
legend_handles = []
legend_labels = []

for ax in [ax1, ax2]:
    handles, labels = ax.get_legend_handles_labels()
    legend_handles.extend(handles)
    legend_labels.extend(labels)

# Draw a new legend in one of the subplots (here we choose ax1)
ax1.legend(legend_handles, legend_labels, fontsize=25, loc=(0, 0.3))

plt.savefig('../figure/draw_AlternativeOptimizationChoice_LineChartconfig5.png',bbox_inches='tight')
plt.savefig('../figure/draw_AlternativeOptimizationChoice_LineChartconfig5.svg',bbox_inches='tight')
