import re

with open('src-tauri/src/crypto.rs', 'r') as f:
    content = f.read()

content = content.replace("1568", "ML_KEM_1024_CT_SIZE")
content = content.replace("3309", "ML_DSA_65_SIG_SIZE")
content = content.replace("1952", "ML_DSA_65_VK_SIZE")
content = content.replace("4032", "ML_DSA_65_SK_SIZE")
content = content.replace("3314", "PAYLOAD_OFFSET_WITH_MAGIC")
content = content.replace("3310", "PAYLOAD_OFFSET_LEGACY")

with open('src-tauri/src/crypto.rs', 'w') as f:
    f.write(content)
