# ------------------------------------------------------------------- #
# Auxiliary file to generate contraints for PUF placement
# Target : Ultrascale+ FPGAs (ZCU104)
# Ilias Papalamprou <ipapalambrou@microlab.ntua.gr>
# ------------------------------------------------------------------- #

# ------------------------------------------------------------------- #
# PARAMETERS -------------------------------------------------------- #

# X-Y coordinates for ZCU104 board in X1Y2 clock region
x_array = [49, 50, 53, 54, 56, 57, 61]
y_array = list(range(120, 180))

# Path name from synthesized design
# path_name = "GEN_PUF"
# path_name = "PUF_MODULE/GEN_PUF"
path_name = "design_1_i/axi4lite_0/inst/PUF_MODULE/GEN_PUF"

# Number of PUF cells
cell_count = 128

# Output file name (in Vivado project)
output_file = "../constraints/puf_constraints_zcu104.xdc"

# ------------------------------------------------------------------- #
# FUNCTIONS --------------------------------------------------------- #
def generate_file_header(path_name, file_name):
	header_lines = [
		"# --- File automatically generated with gen_constraints.py --- #",
		"",
		"set_property BEL D6LUT [get_cells -hierarchical -regexp .*GEN_PUF.*/SRLC32E_inst_3]",
		"set_property BEL C6LUT [get_cells -hierarchical -regexp .*GEN_PUF.*/SRLC32E_inst_2]",
		"set_property BEL B6LUT [get_cells -hierarchical -regexp .*GEN_PUF.*/SRLC32E_inst_1]",
		"set_property BEL A6LUT [get_cells -hierarchical -regexp .*GEN_PUF.*/SRLC32E_inst_0]",
		"",
		"set_property BEL DFF [get_cells -hierarchical -regexp .*GEN_PUF.*/FDCPE_inst]",
		""
	]

	for line in header_lines:
		file_name.write(line + "\n")


def generate_line_code(cell, x, y, path_name):
	lines = []
	lines.append(f"# ---- CELL {cell} --- #")
	lines.append(f"set_property LOC SLICE_X{x}Y{y} [get_cells -hierarchical -regexp .*GEN_PUF.{cell}..PUF/SRLC32E_inst.*]")
	lines.append(f"set_property BEL A6LUT [get_cells {{{path_name}[{cell}].PUF/SRLC32E_inst_0}}]")
	lines.append(f"set_property BEL B6LUT [get_cells {{{path_name}[{cell}].PUF/SRLC32E_inst_1}}]")
	lines.append(f"set_property BEL C6LUT [get_cells {{{path_name}[{cell}].PUF/SRLC32E_inst_2}}]")
	lines.append(f"set_property BEL D6LUT [get_cells {{{path_name}[{cell}].PUF/SRLC32E_inst_3}}]")
	lines.append(f"set_property LOC SLICE_X{x}Y{y} [get_cells -hierarchical -regexp .*{path_name}.{cell}..PUF/FDCPE_inst]")
	lines.append(f"set_property BEL DFF [get_cells {{{path_name}[{cell}].PUF/FDCPE_inst}}]")
	lines.append(f"set_property LOC SLICE_X{x}Y{y} [get_cells -hierarchical -regexp .*{path_name}.{cell}..PUF/CARRY8_inst]")
	lines.append("")
	return lines

# ------------------------------------------------------------------- #
# MAIN -------------------------------------------------------------- #
def main():
	# Generate placement contraints and save them to file
	with open(output_file, "w") as file:
		# Write file header
		generate_file_header(path_name, file)

		# Loop for each PUF cell
		cell = 0
		for x in x_array:
			for y in y_array:
				if cell < cell_count:
					generated_lines = generate_line_code(cell, x, y, path_name)

					# Save to file
					for line in generated_lines:
						file.write(line + "\n")
					cell += 1

				# Break when desired cell number is reached
				else:
					break

	print("Done generating contraints")

if __name__ == "__main__":
		main()
