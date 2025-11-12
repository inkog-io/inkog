#!/bin/bash

# Create pattern tests 2-6 from pattern 1 template
# Customize for each pattern

for pattern_num in 2 3 4 5 6; do
    case $pattern_num in
        2)
            PATTERN_NAME="hardcoded-credentials-v2"
            DESC="Hardcoded Credentials Detection"
            FINDINGS_MIN=15
            FINDINGS_MAX=25
            FINDINGS_MESSY_MIN=50
            FINDINGS_MESSY_MAX=85
            ;;
        3)
            PATTERN_NAME="infinite-loops-v2"
            DESC="Infinite Loops Detection"
            FINDINGS_MIN=30
            FINDINGS_MAX=50
            FINDINGS_MESSY_MIN=30
            FINDINGS_MESSY_MAX=60
            ;;
        4)
            PATTERN_NAME="unsafe-env-access-v2"
            DESC="Unsafe Environment Access Detection"
            FINDINGS_MIN=10
            FINDINGS_MAX=20
            FINDINGS_MESSY_MIN=35
            FINDINGS_MESSY_MAX=70
            ;;
        5)
            PATTERN_NAME="token-bombing-v2"
            DESC="Token Bombing Detection"
            FINDINGS_MIN=25
            FINDINGS_MAX=45
            FINDINGS_MESSY_MIN=30
            FINDINGS_MESSY_MAX=60
            ;;
        6)
            PATTERN_NAME="recursive-tool-calling-v2"
            DESC="Recursive Tool Calling Detection"
            FINDINGS_MIN=20
            FINDINGS_MAX=35
            FINDINGS_MESSY_MIN=20
            FINDINGS_MESSY_MAX=45
            ;;
    esac

    # Create the test file
    sed "s|PATTERN_NUMBER=1|PATTERN_NUMBER=$pattern_num|g; \
         s|Prompt Injection|$DESC|g; \
         s|pattern-1-v2|$PATTERN_NAME|g; \
         s|EXPECTED_FINDINGS_CLEAN_MIN=20|EXPECTED_FINDINGS_CLEAN_MIN=$FINDINGS_MIN|g; \
         s|EXPECTED_FINDINGS_CLEAN_MAX=30|EXPECTED_FINDINGS_CLEAN_MAX=$FINDINGS_MAX|g; \
         s|EXPECTED_FINDINGS_MESSY_MIN=25|EXPECTED_FINDINGS_MESSY_MIN=$FINDINGS_MESSY_MIN|g; \
         s|EXPECTED_FINDINGS_MESSY_MAX=40|EXPECTED_FINDINGS_MESSY_MAX=$FINDINGS_MESSY_MAX|g; \
         s|HARD GATE 1|HARD GATE $pattern_num|g; \
         s|Pattern 1 -|Pattern $pattern_num -|g; \
         s|Pattern \$PATTERN_NUMBER Test|Pattern $pattern_num Test|g" \
        /private/tmp/inkog-demo/validation/pattern-1-test.sh > \
        /private/tmp/inkog-demo/validation/pattern-$pattern_num-test.sh

    chmod +x /private/tmp/inkog-demo/validation/pattern-$pattern_num-test.sh
    echo "✓ Created pattern-$pattern_num-test.sh"
done

echo ""
echo "All pattern tests created!"
