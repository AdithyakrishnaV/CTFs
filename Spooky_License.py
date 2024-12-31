import angr
import claripy #symbolic representation of a license key


project = angr.Project("./spookylicence", auto_load_libs=False)
#prevent automatically loding external/shared dependencies into the analysis

license_length = 32 #32 characters long
license_input = claripy.BVS("license", license_length * 8)
#creates a symbolic binary representation

#create initial state with symbolic license as input
state = project.factory.entry_state(
    args=["./spookylicence", license_input]
)

#  uninitialized memory  & registers  filled with zeros during execution
state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS)

#  ensures the license consists only of printable ASCII characters
for i in range(license_length):
    state.solver.add(license_input.get_byte(i) >= ord(" "))# character must be greater than or equal to ASCII value 32
    state.solver.add(license_input.get_byte(i) <= ord("~"))# less than or equal to ASCII value 126 

# create simulation manager, handle different execution paths
manager = project.factory.simulation_manager(state)

# success and failure addresses
success_address = 0x400000+0x187d ;  # Call Address of "License Correct"
failure_address = 0x400000+0x1890 ;  # Call Address of "License Invalid"
#offset in the binary where the "License Correct" message is triggered 

#angr automatically loads PIE binaries at 0x400000
# call addresses for these messages correspond to the locations in the binary where these outcomes are triggered

# direct the symbolic execution to explore paths & find paths that reach the success address
manager.explore(find=success_address, avoid=failure_address)

# Check if a valid license was found
if manager.found:
    found_state = manager.found[0]
    solution = found_state.solver.eval(license_input, cast_to=bytes)
    print(f"Valid License: {solution.decode()}")
else:
    print("No valid license found.")
