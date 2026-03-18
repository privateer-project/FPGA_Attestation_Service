#create_pblock PUF_Block_Zone
#add_cells_to_pblock [get_pblocks PUF_Block_Zone] [get_cells -hierarchical -regexp .*puf.*gen.*/.*/.*/.*]
#add_cells_to_pblock [get_pblocks PUF_Block_Zone] [get_cells {CHOICE_puf_gen_uplus/CHOICE_PUF_gen_0 CHOICE_puf_gen_uplus/xadc_wiz_0/U0/AXI_XADC_CORE_I/XADC_INST}]

#add_cells_to_pblock [get_pblocks PUF_Block_Zone] [get_cells -hierarchical -regexp .*puf.*gen.*/.*/.*/.*]

create_pblock PUF_Block_Zone
add_cells_to_pblock [get_pblocks PUF_Block_Zone] [get_cells -hierarchical -regexp .*PUF_MODULE.*/.*]
add_cells_to_pblock [get_pblocks PUF_Block_Zone] [get_cells PUF_MODULE]
resize_pblock [get_pblocks PUF_Block_Zone] -add {CLOCKREGION_X1Y2:CLOCKREGION_X1Y2}
set_property CONTAIN_ROUTING 1 [get_pblocks PUF_Block_Zone]
set_property EXCLUDE_PLACEMENT 1 [get_pblocks PUF_Block_Zone]
add_cells_to_pblock [get_pblocks PUF_Block_Zone] [get_cells -hier -regexp .*PUF_MODULE]


# Contraint without block design
# add_cells_to_pblock [get_pblocks PUF_Block_Zone] [get_cells {PUF_MODULE}]



