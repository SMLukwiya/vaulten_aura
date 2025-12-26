from conan import ConanFile
from conan.tools.gnu import Autotools, AutotoolsToolchain
from conan.tools.layout import basic_layout
from conan.tools.files import chdir
from conan.tools.scm import Git
import os

class LibyamlRecipe(ConanFile):
    name = "yaml"
    version = "0.2.5"
    package_type = "library"
    settings = "os", "compiler", "build_type", "arch"

    options = {"shared": [True, False]}
    default_options = {"shared": False}

    def source(self):
        git = Git(self)
        git.clone(url = "https://github.com/yaml/libyaml", target=".")
        git.checkout(commit="840b65c40675e2d06bf40405ad3f12dec7f35923") # source pinned on this commit

    def layout(self):
        basic_layout(self)

    def generate(self):
        tc = AutotoolsToolchain(self)
        tc.generate()

    # this build follows the libyaml project build instructions on github
    def build(self):
        with chdir(self, self.source_folder):
            if os.path.exists("bootstrap"):
                self.run("./bootstrap")
        autotools = Autotools(self)
        autotools.configure()
        autotools.make()

    def package(self):
        autotools = Autotools(self)
        autotools.install()

    def package_info(self):
        self.cpp_info.libs = ["yaml"]
