text = ""
for i in range(1, 9901):
    text += f"{i}\n"


with open("tmp.txt", "w") as f:
    f.write(text)
    
