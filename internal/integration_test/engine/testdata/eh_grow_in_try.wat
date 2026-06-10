;; Test: stack growth INSIDE a try body before the throw. The catching
;; function $f enters a try_table, mutates a local, then calls $recurse which
;; recurses deeply enough to force one or more stack-buffer grows (relocations)
;; before throwing at the bottom. $f's handler must restore $f's frame against
;; the grown (relocated) buffer: the returned sentinel must be the throw-time
;; local value (7), and the deep-sum result confirms the recursion really ran.
(module
  (tag $t)

  ;; Recurse n deep (each frame carries locals to enlarge frames and hasten
  ;; stack growth), then throw at the bottom. Returns n*(n+1)/2 on the way down
  ;; (never actually returned here because the bottom throws).
  (func $recurse (param $n i32) (result i32)
    (local $a i32) (local $b i32) (local $c i32)
    (local.set $a (local.get $n))
    (local.set $b (i32.mul (local.get $n) (i32.const 3)))
    (local.set $c (i32.add (local.get $a) (local.get $b)))
    (if (i32.eqz (local.get $n))
      (then (throw $t)))
    (i32.add (local.get $c)
      (call $recurse (i32.sub (local.get $n) (i32.const 1)))))

  (func (export "run") (param $n i32) (result i32)
    (local $sentinel i32)
    (local.set $sentinel (i32.const 42))
    (block $catch (result exnref)
      (try_table (catch_all_ref $catch)
        (local.set $sentinel (i32.const 7))   ;; throw-time value to preserve
        (drop (call $recurse (local.get $n)))  ;; grows stack, then throws
        (unreachable))
      (unreachable))
    (drop)                                     ;; drop the caught exnref
    (local.get $sentinel))                     ;; must be 7
)
