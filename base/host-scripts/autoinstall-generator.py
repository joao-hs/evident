from jinja2 import Environment
import yaml
import sys

# Create a Jinja2 Environment object
env = Environment()

# Ensure the correct number of arguments are provided
if len(sys.argv) != 3 and len(sys.argv) != 4:
    print("Usage: python autoinstall-generator.py <template_file_path> <data_file_path> [output_file_path]")
    sys.exit(1)

# Assign command line arguments to variables
template_file_path = sys.argv[1]
data_file_path = sys.argv[2]
output = sys.stdout
if len(sys.argv) == 4:
    output = open(sys.argv[3], 'w')

# Define your template as a string
# Read the template string from a file
with open(template_file_path, 'r') as file:
    template_string = file.read()

# Load the template
template = env.from_string(template_string)

# Data to be passed to the template
# Load data from a YAML file
with open(data_file_path, 'r') as yaml_file:
    data = yaml.safe_load(yaml_file)

# Render the template with the data
rendered_template = template.render(data)

# Print the output
print(rendered_template, file=output)

output.close()
