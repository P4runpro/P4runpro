import matplotlib.pyplot as plt
import numpy as np

plt.figure(figsize=(12, 8))

x = ['PHV', 'Hash', 'SRAM', 'TCAM', 'VLIW', 'SALU', 'LTID']
plt.yticks([0, 0.2, 0.4, 0.6, 0.8, 1.0])

plt.xticks(fontsize=31)
plt.yticks(fontsize=40)

a = [0.29, 0.92, 0.44, 0.94, 0.97, 0.56, 0.15]

size = 7
xx = np.arange(size)
plt.xlim()

plt.ylim(bottom=0, top=1)

# Width of each type of bar
width = 0.2

# Draw the bar chart
pic1=plt.bar(xx, a, width=width, label="a", color='#ED3333', zorder=0, hatch='/')
plt.bar(xx, a, width=width, label="a", edgecolor='black', color='none', lw=1, zorder = 1 )

# Set the x-axis tick labels to the values in the x list
plt.xticks(xx, x)

# Add labels to the x and y axes
plt.xlabel('Resource Type', fontsize=40, fontweight='bold')
plt.ylabel('Resource Utilization', fontsize=40, fontweight='bold')

# Add horizontal and vertical grid lines
plt.grid(axis='both', linestyle='--', color='gray', alpha=0.7)

# Choose the items to display
handles = [pic1]
labels = ['P4runpro']

plt.legend(handles=handles, labels=labels, edgecolor="#000000", prop={'size': 24}, loc='upper right')

# Display the bar chart
# plt.show()

plt.savefig('../figure/draw_ResourceOverhead.png',bbox_inches='tight')
plt.savefig('../figure/draw_ResourceOverhead.svg',bbox_inches='tight')
