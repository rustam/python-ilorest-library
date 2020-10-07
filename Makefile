UNZIP=$(shell which unzip)
EXPORT=$(shell which export)
FIND=$(shell which find)
ECHO=$(shell which echo)
RM=$(shell which rm)
PYTHON=$(shell which python)
PYLINT=$(shell which pylint)
NOSE=$(shell which nosetests)
CREATE_CHROOT := /net/blofly.us.rdlabs.hpecorp.net/data/blofly/iss-linux-sdk/chrootbuilder/create_chroot.sh
CHROOT := /net/blofly.us.rdlabs.hpecorp.net/data/blofly/iss-linux-sdk/chrootbuilder/tools/muchroot
BUILD_DIR := $(shell pwd)/.blddir
SOURCEDIR := $(shell pwd)/
ZYPPER := zypper --non-interactive install


all: bdist-rpm bdist-rpm-python3

bdist-rpm:
	zypper --non-interactive install rpm-build 
	$(eval DIR=$(shell pwd))
	$(eval ILOREST=$(DIR)/ilorest/src)
	$(eval PYTHONPATH=$(ILOREST):$(PYTHONPATH))
	mkdir ${MTX_COLLECTION_PATH}/python2/
	tar xfz ./packaging/ext/setuptools-2.2.tar.gz
	cd ./setuptools-2.2 && \
	$(PYTHON) setup.py install
	tar xfz ./packaging/ext/PySocks-1.6.8.tar.gz
	cd ./PySocks-1.6.8 && \
	$(PYTHON) setup.py install
	unzip ./packaging/ext/recordtype-1.1.zip
	cd ./recordtype-1.1 && \
	$(PYTHON) setup.py bdist_rpm --dist-dir ${MTX_COLLECTION_PATH}/python2/
	tar xfz ./packaging/ext/pypandoc-1.4.tar.gz
	cd ./pypandoc-1.4 $$ \
	$(PYTHON) setup.py install
	tar xfz ./packaging/ext/jsonpointer-1.10.tar.gz
	cd ./jsonpointer-1.10 && \
	iconv -f 'UTF-8' -t 'ASCII//TRANSLIT//IGNORE' jsonpointer.py > jp && \
	cp -f jp jsonpointer.py
	cd ./jsonpointer-1.10 && \
	rm jp
	cd ./jsonpointer-1.10 && \
	$(PYTHON) setup.py bdist_rpm --dist-dir ${MTX_COLLECTION_PATH}/python2/
	tar xfz ./packaging/ext/jsonpatch-1.16.tar.gz
	cd ./jsonpatch-1.16 && \
	iconv -f 'UTF-8' -t 'ASCII//TRANSLIT//IGNORE' jsonpatch.py > jp && \
	cp -f jp jsonpatch.py
	cd ./jsonpatch-1.16 && \
	rm jp
	cd ./jsonpatch-1.16 && \
	$(PYTHON) setup.py bdist_rpm --dist-dir ${MTX_COLLECTION_PATH}/python2/
	tar xfz ./packaging/ext/jsonpath-rw-1.4.0.tar.gz
	cd ./jsonpath-rw-1.4.0 && \
	$(PYTHON) setup.py bdist_rpm --dist-dir ${MTX_COLLECTION_PATH}/python2/
	tar xfz ./packaging/ext/decorator-4.1.2.tar.gz
	cd ./decorator-4.1.2 && \
	$(PYTHON) setup.py bdist_rpm --dist-dir ${MTX_COLLECTION_PATH}/python2/
	tar xfz ./packaging/ext/six-1.10.0.tar.gz
	cd ./six-1.10.0 && \
	$(PYTHON) setup.py bdist_rpm --dist-dir ${MTX_COLLECTION_PATH}/python2/
	tar xfz ./packaging/ext/urllib3-1.23.tar.gz
	cd ./urllib3-1.23 && \
	$(PYTHON) setup.py bdist_rpm --dist-dir ${MTX_COLLECTION_PATH}/python2/
	tar xfz ./packaging/ext/ply-3.10.tar.gz
	cd ./ply-3.10 && \
	$(PYTHON) setup.py bdist_rpm --dist-dir ${MTX_COLLECTION_PATH}/python2/
	$(PYTHON) setup.py bdist_rpm --dist-dir ${MTX_COLLECTION_PATH}/python2/
	rm -rf ${MTX_COLLECTION_PATH}/*.src.rpm
	rm -rf ${MTX_COLLECTION_PATH}/python2/*.src.rpm


define build-pkg
	tar xfz $(BUILD_DIR)/buildpwd/packaging/ext/$1* -C $(BUILD_DIR)/buildpwd/
	$(CHROOT) $(BUILD_DIR) bash -c 'cd /buildpwd/$1 && python3 setup.py bdist_rpm --dist-dir /collection/'
	rm -r $(BUILD_DIR)/buildpwd/$1
endef

export LC_ALL=en_US.UTF-8
export PYTHONIOENCODING=utf-8
bdist-rpm-python3:
	$(CREATE_CHROOT) -d SLES15 -D $(BUILD_DIR)
	$(CHROOT) $(BUILD_DIR) $(ZYPPER) python3 python3-setuptools
	mkdir -p $(BUILD_DIR)/buildpwd $(BUILD_DIR)/collection/
	cp -a $(SOURCEDIR)* $(BUILD_DIR)/buildpwd

	$(call build-pkg,recordtype-1.3)
	$(call build-pkg,pypandoc-1.4)
	$(call build-pkg,jsonpointer-2.0)
	$(call build-pkg,jsonpatch-1.23)
	$(call build-pkg,jsonpath-rw-1.4.0)
	$(call build-pkg,decorator-4.1.2)
	$(call build-pkg,urllib3-1.23)
	$(call build-pkg,ply-3.10)
	$(call build-pkg,pypandoc-1.4)
	$(call build-pkg,six-1.10.0)
	#cd $(BUILD_DIR)/collection/ && rename "" python3- *.rpm
	$(CHROOT) $(BUILD_DIR) bash -c 'cd /buildpwd/ && python3 setup.py bdist_rpm --dist-dir /collection/'
	#cd $(BUILD_DIR)/collection/ && rename python- python3- *.rpm
	mkdir ${MTX_COLLECTION_PATH}/python3/
	mv $(BUILD_DIR)/collection/*.noarch.rpm ${MTX_COLLECTION_PATH}/python3/
	rm -rf ${MTX_COLLECTION_PATH}/*.src.rpm
	rm -rf ${MTX_COLLECTION_PATH}python3/*.src.rpm