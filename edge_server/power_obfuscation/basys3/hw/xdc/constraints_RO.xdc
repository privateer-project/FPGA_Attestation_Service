set_property DONT_TOUCH true [get_cells -hierarchical -filter {NAME =~ *ro_inst*}]

set_property ALLOW_COMBINATORIAL_LOOPS true [get_nets -of_objects [get_cells -hierarchical -filter {NAME =~ "ro_inst/gen_ros*/*"}]]

set_property SEVERITY {Warning}  [get_drc_checks LUTLP-1]

set_property SEVERITY {Warning} [get_drc_checks NSTD-1]

create_pblock pblock_ro
add_cells_to_pblock [get_pblocks pblock_ro] [get_cells -quiet [list ro_inst/*]]
resize_pblock [get_pblocks pblock_ro] -add {SLICE_X0Y150:SLICE_X30Y190}
set_property CONTAIN_ROUTING true [get_pblocks pblock_ro]
set_property EXCLUDE_PLACEMENT true [get_pblocks pblock_ro]
set_property KEEP_HIERARCHY true [get_cells ro_inst]