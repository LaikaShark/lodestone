#ifndef LODESTONE_H
#define LODESTONE_H

#include <stdint.h>
#include <string>
#include <vector>

class Binary;
class Section;
class Symbol;

class Symbol
{
  public:
    enum SymType
    {
      SYM_TYPE_UKN = 0,
      SYM_TYPE_FNC = 1
    };

    Symbol() : type(SYM_TYPE_UKN), name(), addr(0) {}

    SymType     type;
    std::string name;
    uint64_t    addr;
};

class Section
{
  public:
    enum SecType
    {
      SEC_TYPE_NONE = 0,
      SEC_TYPE_CODE = 1,
      SEC_TYPE_DATA = 2
    };

    Section() : binary(NULL), type(SEC_TYPE_NONE), vma(0), size(0), bytes(NULL) {}
    
    //Check if this section contains a given address
    bool contains(uint64_t addr)
    {
      return (addr >= vma) && (addr - vma < size);
    }

    Binary      *binary;
    std::string name;
    SecType     type;
    uint64_t    vma; //virtual memory address
    uint64_t    size;
    uint8_t     *bytes;
};

class Binary
{
  public:
    enum BinType
    {
      BIN_TYPE_AUTO = 0,
      BIN_TYPE_ELF  = 1,
      BIN_TYPE_PE   = 2
    };

    enum BinArch
    {
      ARCH_NONE = 0,
      ARCH_X86  = 1
    };

    Binary() : type(BIN_TYPE_AUTO), arch(ARCH_NONE), bits(0), entry(0) {}

    Section* get_text_section()
    {
      for(auto &sec : secs)
        if(sec.name == ".text")
          return &sec;
      return NULL;
    }

    std::string   filename;
    BinType       type;
    std::string   type_str;
    BinArch       arch;
    std::string   arch_str;
    unsigned      bits;
    uint64_t      entry;
    std::vector<Section>  secs;
    std::vector<Symbol>   syms;
};

int load_bin(std::string &fname, Binary* bin, Binary::BinType type);
void unload_bin(Binary* bin);

#endif
