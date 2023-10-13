import oraexe
bt = open(r"test.exe", "rb").read()
exe = oraexe.P1(bt)
print(exe.rel_tb[0]["addr"])
