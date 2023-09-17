from conans import ConanFile, tools

class DDoSConan(ConanFile):
    name = "ACL"
    version = "0.1"
    settings = None
    description = "ACL Defence mechanism"
    url = "None"
    license = "None"
    author = "None"
    topics = None

    def package(self):
        self.copy("*")

    def package_info(self):
        self.cpp_info.libs = tools.collect_libs(self)
