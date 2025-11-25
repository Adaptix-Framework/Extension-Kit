SUBDIRS := AD-BOF Creds-BOF Elevation-BOF Execution-BOF Injection-BOF LateralMovement-BOF Postex-BOF Process-BOF SAL-BOF SAR-BOF UnderlayCopy-BOF

.PHONY: all $(SUBDIRS) clean

all: $(SUBDIRS)
$(SUBDIRS):
	@echo "=====>>  $@"
	@$(MAKE) --no-print-directory -C $@
	@echo ""

clean:
	@for dir in $(SUBDIRS); do \
		$(MAKE) --no-print-directory -C $$dir clean; \
	done