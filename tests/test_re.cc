#include <iostream>
#include <regex>
#include <string>

//  (                  # media-range capturing-parenthesis
//    [^\s;,]+              # type/subtype
//    (?:[ \t]*;[ \t]*      # ";"
//      (?:                 # parameter non-capturing-parenthesis
//        [^\s;,q][^\s;,]*  # token that doesn't start with "q"
//      |                   # or
//        q[^\s;,=][^\s;,]* # token that is more than just "q"
//      )
//    )*                    # zero or more parameters
//  )                       # end of media-range
//  (?:[ \t]*;[ \t]*q=      # weight is a "q" parameter
//    (\d*(?:\.\d+)?)       # qvalue capturing-parentheses
//    [^,]*                 # "extension" accept params: who cares?
//  )?

int main() {
  std::string header = "Accept-Encoding: gzip;q=0.8, compress, deflate;q=0.5, br;q=1.0";
  //std::regex re(R"(([^\s;,]+(?:[ \t]*;[ \t]*(?:[^\s;,q][^\s;,]*|q[^\s;,=][^\s;,]*))*)(?:[ \t]*;[ \t]*q=(\d*(?:\.\d+)?)[^,]*)?)");
  std::regex re(
      R"(()"
        R"([^\s;,]+)"
        R"((?:[ \t]*;[ \t]*)"
          R"((?:)"
            R"([^\s;,q][^\s;,]*)"
          R"(|)"
            R"(q[^\s;,=][^\s;,]*)"
          R"())"
        R"()*)"
      R"())"
      R"((?:[ \t]*;[ \t]*q=)"
        R"((\d*(?:\.\d+)?))"
        R"([^,]*)"
      R"()?)"
    );
  std::smatch match;
  
  std::string::const_iterator searchStart(header.cbegin());
  while (std::regex_search(searchStart, header.cend(), match, re)) {
    std::string encoding = match[1].matched ? match[1].str() : match[4].str();
    std::string qvalue = match[2].matched ? match[2].str() : "1.0";
    
    std::cout << "Encoding: " << encoding << ", q=" << qvalue << std::endl;
    
    searchStart = match.suffix().first;
  }

  return 0;
}
