#!/bin/bash

cd /Users/branedev/Documents/Work/automation_stuff/copy_from_qcafe_to_datasetresults/ws/tempo_pr_pratik/sept1

# For each language, create new branch from main and copy content
for lang in cpp csharp go java javascript kotlin php python ruby scala typescript; do
    echo "Fixing $lang branch..."
    
    # Save current content
    git checkout $lang
    cp -r . /tmp/${lang}_content
    
    # Create new branch from main
    git checkout main
    git branch -D ${lang}_new 2>/dev/null || true
    git checkout -b ${lang}_new
    
    # Copy language content (excluding .git)
    rsync -av --exclude='.git' /tmp/${lang}_content/ .
    
    # Clean up - keep only language-specific content
    find . -maxdepth 1 -type d -name "[a-z]*" ! -name "$lang" ! -name "CWE-*" ! -name "Best_Practices" -exec rm -rf {} + 2>/dev/null || true
    
    git add -A
    git commit -m "Add $lang security test cases"
    
    # Force push new branch
    git push -f origin ${lang}_new:$lang
    
    # Clean up temp
    rm -rf /tmp/${lang}_content
done

echo "All branches fixed with proper history from main"