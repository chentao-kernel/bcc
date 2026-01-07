enable_language(CXX)
set(BCC_SRC ${CMAKE_CURRENT_SOURCE_DIR}/../../src/cc)
set(bcc_syms_sources bcc_sym_api.cc ${BCC_SRC}/bcc_syms.cc ${BCC_SRC}/bcc_elf.c
	${BCC_SRC}/bcc_perf_map.c ${BCC_SRC}/bcc_proc.c ${BCC_SRC}/common.cc
	${BCC_SRC}/api/BPFTable.cc ${BCC_SRC}/bcc_zip.c ${BCC_SRC}/libbpf.c
	${BCC_SRC}/perf_reader.c)

add_definitions(-w)

add_library(bcc-syms-static STATIC ${bcc_syms_sources} )
target_compile_options(bcc-syms-static PRIVATE -fpermissive)
target_link_libraries(bcc-syms-static elf z)
set_target_properties(bcc-syms-static  PROPERTIES OUTPUT_NAME bcc-syms)
target_include_directories(bcc-syms-static PUBLIC ${BCC_SRC} ${BCC_SRC}/api)

add_library(bcc-syms SHARED ${bcc_syms_sources})
target_compile_options(bcc-syms PRIVATE -fpermissive)
target_link_libraries(bcc-syms elf z)
target_include_directories(bcc-syms PUBLIC ${BCC_SRC} ${BCC_SRC}/api)


install(TARGETS bcc-syms bcc-syms-static DESTINATION )
install(FILES ../../src/cc/bcc_syms.h ../../src/cc/bcc_proc.h DESTINATION include/bcc_syms)
