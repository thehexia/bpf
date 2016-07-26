#ifndef FILE_HPP
#define FILE_HPP

#include <string>
#include <iostream>
#include <fstream>

namespace bpf_test
{

using String = std::string;

struct File
{
  File(String filename)
    : filename_(filename), file_(filename.c_str())
  { }

  ~File() { if (file_.is_open()) file_.close(); }

  String read();

private:
  String filename_;
  std::ifstream file_;
};


String
File::read()
{
  String content;

  file_.seekg(0, std::ios::end);
  content.reserve(file_.tellg());
  file_.seekg(0, std::ios::beg);

  content.assign((std::istreambuf_iterator<char>(file_)),
              std::istreambuf_iterator<char>());

  return content;
}


} // namespace bpf_test

#endif
