# Demos

1. Open GPEDIT.msc (right-click Start, Run: GPEDIT.msc)
2. Navigate to: Computer Configuration > Windows Settings > Security Settings > Advanced Audit Policy Configuration > System Audit Policys - Local Group Policy Object > Detail Tracking
3. Audit Process Creation: Enable > Success
4. GPUPDATE /FORCE
