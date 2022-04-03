initSidebarItems({"constant":[["CFG_TARGET","Offset of decrypted config in flash."],["ENCRYPTED_CFG","Offset of encrypted config in flash."],["ENCRYPTED_FW","Offset of encrypted firmware in flash."],["ENCRYPTED_MSG","Offset of encrypted release message in flash."],["FW_TARGET","Offset of decrypted firmware in SRAM."],["MAX_DECRYPTED_FW_LEN","Maximum decrypted firmware image length."],["MAX_ENCRYPTED_CFG_LEN","Maximum encrypted config image length."],["MAX_ENCRYPTED_FW_LEN","Maximum encrypted firmware image length."],["MAX_ENCRYPTED_MSG_LEN","Maximum encrypted release message length."]],"fn":[["authenticate","Verifies the authenticity of the host-tools currently communicating with the bootloader."],["decrypt_and_send_rel_msg","Simultaneously decrypts, hashes, and sends the release message back to host-tools."],["decrypt_hash","Decrypts and hashes simultaneously."],["decrypt_to_flash","Decrypts the provided ciphertext, incrementally flashing it to the specified flash offset."],["decrypt_to_sram","Decrypts an encrypted image stored on flash and writes the plaintext to a specified region in SRAM."]],"struct":[["DynCompMeta","Metadata for dynamically-sized components sent by host-tools."],["Hashes","Wrapper around component hashes of a package sent over UART."]]});