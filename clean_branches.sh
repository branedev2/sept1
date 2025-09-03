#!/bin/bash

cd /Users/branedev/Documents/Work/automation_stuff/copy_from_qcafe_to_datasetresults/ws/tempo_pr_pratik/sept1

# Clean javascript branch
git checkout javascript
rm -rf csharp java kotlin scala typescript
git add -A
git commit -m "Clean up extra language directories from javascript branch"
git push origin javascript

# Clean typescript branch  
git checkout typescript
rm -rf csharp java javascript kotlin scala
git add -A
git commit -m "Clean up extra language directories from typescript branch"
git push origin typescript

echo "Cleaned up javascript and typescript branches"