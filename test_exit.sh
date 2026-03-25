#!/usr/bin/env bash
f() {
  exit 1
}
if f >/dev/null 2>&1; then
  echo "Success"
else
  echo "Failure"
fi
echo "After"
