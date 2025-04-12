#include <capstone/capstone.h>
#include <elf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#define error(...)                                                             \
  {                                                                            \
    fprintf(stderr, __VA_ARGS__);                                              \
    exit(-1);                                                                  \
  }
#define err_str "please enter a valid elf file and amount of instructions!\n"
int main(int argc, char **argv) {
  if (argc != 3)
    error(err_str) const int amount = atoi(argv[2]);
  const char * const ignore[] = {"hlt",  "cli",  "sti",   "in",    "ins",  "out",  "outs",
                    "lgdt", "lidt", "lmsw",  "smsw",  "ud2",  "jmp",  "je",
                    "jz",   "jne",  "jnz",   "ja",    "jnbe", "jae",  "jnb",
                    "jb",   "jnae", "jbe",   "jna",   "jg",   "jnle", "jge",
                    "jnl",  "jl",   "jnge",  "jle",   "jng",  "jo",   "jno",
                    "js",   "jns",  "jp",    "jpe",   "jnp",  "jpo",  "jc",
                    "jnc",  "jcxz", "jecxz", "jrcxz", "call", "ret",  NULL};
  FILE *fp = fopen(argv[1], "rb");
  if (!fp)
    error(err_str);
  Elf64_Ehdr ehdr;
  fread(&ehdr, 1, sizeof ehdr, fp);
  fseek(fp, ehdr.e_shoff, SEEK_SET);
  Elf64_Shdr *shdr = malloc(sizeof ehdr * ehdr.e_shnum);
  fread(shdr, sizeof ehdr, ehdr.e_shnum, fp);
  Elf64_Shdr shstrtab = shdr[ehdr.e_shstrndx];
  size_t sh_size = shstrtab.sh_size, start = 0, end = 0, addr = 0;
  char * const shstrtab_data = malloc(sh_size);
  fseek(fp, shstrtab.sh_offset, SEEK_SET);
  if (!fread(shstrtab_data, 1, shstrtab.sh_size, fp))
    error(err_str);
  for (int i = 0; i < ehdr.e_shnum; i++)
    if (!strcmp(&shstrtab_data[shdr[i].sh_name], ".text"))
      start = shdr[i].sh_offset, end = start + shdr[i].sh_size, addr = shdr[i].sh_addr;
  rewind(fp);
  fseek(fp, start, SEEK_SET);
  char fbuf[end];
  fread(fbuf, end, 1, fp);
  fclose(fp);
  free(shdr), free(shstrtab_data);
  csh handle;
  cs_insn *insn;
  cs_open(CS_ARCH_X86, CS_MODE_64, &handle);
  const size_t count = cs_disasm(handle, fbuf, end, addr, 0, &insn);
  for (int i = 0; i < count; i++) {
    if (!strcmp(insn[i].mnemonic, "ret")) {
      const int tmp_size = i - amount + 1;
      if (tmp_size >= 0) {
        for (int j = tmp_size; j < i; j++)
          for (int k = 0; ignore[k]; k++)
            if (!strcmp(insn[j].mnemonic, ignore[k]))
              goto skip;
            for (int j = tmp_size; j <= i; j++)
                printf("0x%02lx: %s %s\n", insn[j].address, insn[j].mnemonic,
                   insn[j].op_str);
            putchar('\n');
        skip:{}
      }
    }
  }
  cs_free(insn, count);
  cs_close(&handle);
}
