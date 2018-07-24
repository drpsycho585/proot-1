/\ypokedata_workaround\y/{pokedata_workaround=strtonum("0x" $2)}
/\y_start\y/{start=strtonum("0x" $2)}
END {
	print "#if defined(__aarch64__)"
	print "#include <unistd.h>"
	print "const ssize_t offset_to_pokedata_workaround=" (pokedata_workaround-start) ";"
	print "#endif /* defined(__aarch64__) */"
}
