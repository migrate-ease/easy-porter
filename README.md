#easy-porter

easy-porter is a smart assistant to help developer to migrate applications from x86 to arm platform. 
It checks the aarch64 compatibility of tasks and provides exact suggestions to help operators migrate efficiently and smoothly. 
As of now, the languages and platforms we support are as follows：

- Java on Linux/Unix
- Python on Linux/Unix 

This tool scans all files in a source tree, regardless of whether they are included by the build system or not. Also it can scan the binary (such as command, so files etc.) or compressed files (such as jar, zip, tar etc.). Currently, the tool supports the following languages/dependencies:

* Java
    * JAR scanning
    * Binary scanning 
    * Dependency versions in pom.xml file
    * Application independent files filtering
    * Compatible version recommendation 
* Python
    * Dependency packages scanning
    * Command calls in python file scanning
    * Binary scanning 
    * Dependency versions in requirements.txt file

For more information on how to modify issues reported, use the tool’s built-in help:

```
python3 easyPorter.py -h
```
# How to run

**Pre-requisites**
- Alinux3 or above (with libxml2-devel and libxslt-devel installed).
```
$ sudo yum install libxml2-devel libxslt-devel -y
```
- Python 3.6.8 or above (with PIP3 module installed).

**Install requirements**
```
$ pip3 install -r requirements.txt
```

**Run tool (console output)**
```
$ python3 easyPorter.py -e java -b -q -d ./examples
```

**Run tool (CSV report)**
```
$ python3 easyPorter.py -e python -b -q -d ./examples -t csv -o result
```

# Sample console report output:
```
$ python3 easyPorter.py -e java -b -q -f ./examples/snappy-java-1.1.8.4.jar -t json 
```
After the above has been executed successfully, you will see a JSON format file at current directory as 'result_$date.json':

```
{
  "objects": "./examples/snappy-java-1.1.8.4.jar",
  "command": "easyPorter.py -e java -b -q -f ./examples/snappy-java-1.1.8.4.jar -t json",
  "executor": "root",
  "time": "Fri Sep  6 14:44:58 CST 2024",
  "node": "test",
  "arch": "aarch64",
  "os": "Alibaba Cloud Linux release 3 (Soaring Falcon)",
  "kernel": "5.10.134-16.3.al8.aarch64",
  "branch": "",
  "commit": "",
  "errors": [],
  "summary": {
    "compatible": 1,
    "incompatible": 0,
    "to_be_verified": 0,
    "others": 0,
    "warning": 0,
    "total": 1
  },
  "details": []
}
```

# License



