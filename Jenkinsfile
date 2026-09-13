// SPDX-FileCopyrightText: 2026 BreachSAFE
// SPDX-License-Identifier: Apache-2.0
//
// QuReddy engine CI. GitHub Actions owns the merge gate (.github/workflows/ci.yml);
// this pipeline covers what Actions cannot: live scans that need an OpenSSL 1.0.2u
// compatibility runtime alongside the pinned 3.5.7 build.
//
// The badssl stage is the reason this file exists. `core.ciphers` rates RC4, DES,
// 3DES, EXPORT, NULL, SEED, IDEA, CAMELLIA and ARIA (#815, #824), and every other
// test for those ratings feeds the classifier cipher *names*. These stages scan
// hosts that negotiate the suites for real.
pipeline {
  agent any

  // These are Jenkins-node capabilities/endpoints, not portable repository
  // defaults. The job must provide them explicitly; an empty value fails the
  // prerequisite stage or disables the optional CBOM publish stage.
  parameters {
    string(name: 'QUREDDY_OPENSSL', defaultValue: '', description: 'Absolute path to the pinned OpenSSL 3.5.x binary on the Jenkins node')
    string(name: 'LEGACY_OPENSSL', defaultValue: '', description: 'Absolute path to the OpenSSL 1.0.2u compatibility binary or shim on the Jenkins node')
    string(name: 'CBOMKIT_API', defaultValue: '', description: 'Optional CBOMkit API base URL for non-blocking artifact publication')
    // A public IKEv2 endpoint, empty by default. It stays empty because a
    // third-party responder is not this project's to probe on every build, and
    // because the one measured here answered fully on two runs of three and
    // degraded to a bare rejection on the other. An operator sets it for a node
    // and an endpoint they have chosen.
    string(name: 'IKE_PUBLIC_TARGET', defaultValue: '', description: 'Public IKEv2 endpoint this node is authorized to scan. Empty skips the IKE stage.')
  }

  options {
    timeout(time: 60, unit: 'MINUTES')
    disableConcurrentBuilds()
    buildDiscarder(logRotator(numToKeepStr: '30'))
  }

  triggers {
    // badssl.com is a third-party endpoint. A nightly run catches a change there
    // as well as a regression here, and the two are distinguishable only by
    // reading which assertion moved.
    cron('H 3 * * *')
  }

  environment {
    REPORT_DIR      = 'build/jenkins'
    QUREDDY_OPENSSL = "${params.QUREDDY_OPENSSL}"
    LEGACY_OPENSSL  = "${params.LEGACY_OPENSSL}"
    CBOMKIT_API     = "${params.CBOMKIT_API}"
    QUREDDY_IKE_PUBLIC_TARGET = "${params.IKE_PUBLIC_TARGET}"
  }

  stages {
    stage('setup') {
      steps {
        sh 'uv sync --frozen --all-extras --dev'
        sh "mkdir -p ${REPORT_DIR}"
      }
    }

    stage('runtimes') {
      // Both binaries are prerequisites, not optional. Assert them here so a
      // missing runtime reads as an environment failure at the top of the log
      // rather than as a skipped test buried in a later stage.
      steps {
        script {
          def legacyOpenSSL = env.LEGACY_OPENSSL?.trim()
          if (!legacyOpenSSL) {
            legacyOpenSSL = sh(
              script: 'for candidate in /opt/openssl-legacy/bin/openssl /Users/paul/Library/Caches/qureddy-app/openssl-legacy-docker/bin/openssl /Users/paul/Library/Caches/qureddy-app/openssl-legacy/bin/openssl; do if [ -x "$candidate" ]; then printf "%s" "$candidate"; break; fi; done',
              returnStdout: true,
            ).trim()
          }
          env.LEGACY_OPENSSL_RESOLVED = legacyOpenSSL
          withEnv(["LEGACY_OPENSSL=${legacyOpenSSL}"]) {
            sh '''
          set -eu
          [ -n "${QUREDDY_OPENSSL:-}" ] || { echo "QUREDDY_OPENSSL Jenkins parameter is required" >&2; exit 1; }
          [ -n "${LEGACY_OPENSSL:-}" ] || { echo "LEGACY_OPENSSL Jenkins parameter is required and no local 1.0.2u candidate was found" >&2; exit 1; }
          "$QUREDDY_OPENSSL" version
          "$QUREDDY_OPENSSL" version | grep -q "OpenSSL 3.5" \\
            || { echo "primary lane is not OpenSSL 3.5.x" >&2; exit 1; }

          "$LEGACY_OPENSSL" version
          "$LEGACY_OPENSSL" version | grep -q "OpenSSL 1.0.2" \\
            || { echo "compatibility lane is not OpenSSL 1.0.2x" >&2; exit 1; }

          # The 1.0.2u runtime is worthless for these targets if its EC math is
          # broken: every modern server picks an ECDHE suite first, the handshake
          # fails client-side, and the sweep reports the host as offering nothing
          # (qureddy#817). A macOS-native 1.0.2u build fails exactly here.
          "$LEGACY_OPENSSL" ecparam -name prime256v1 -genkey -noout > /dev/null \\
            || { echo "compatibility lane cannot do P-256; see qureddy#817" >&2; exit 1; }
            '''
          }
        }
      }
    }

    stage('gates') {
      // The Justfile owns the gate definitions. Calling the recipes keeps this
      // pipeline from drifting into a second, weaker copy of them.
      steps {
        sh 'just lint'
        sh 'just format-check'
        sh 'just typecheck'
      }
    }

    stage('unit') {
      steps {
        sh "uv run --locked pytest tests --ignore=tests/live --ignore=tests/ike_lab " +
           "--cov=qureddy --cov-fail-under=90 -q --junitxml=${REPORT_DIR}/unit.xml"
      }
    }

    stage('live: badssl cipher ratings') {
      environment {
        QUREDDY_LEGACY_OPENSSL = "${LEGACY_OPENSSL_RESOLVED}"
      }
      steps {
        sh "uv run --locked pytest tests/live/test_live_badssl_ciphers.py -q --junitxml=${REPORT_DIR}/badssl.xml"
      }
    }


    stage('live: local sshd') {
      // The only PQ-positive live target in the suite. macOS OpenSSH offers
      // mlkem768x25519-sha256 beside classical ECDH and SHA-1 MACs, so one scan
      // reaches hybrid-offered, classical-alternative, weak-transport and
      // terrapin. It also covers ssh_algorithms.py:143, the SSH call into
      // cipher_primitive, which no TLS test can reach.
      steps {
        sh "uv run --locked pytest tests/live/test_live_ssh_local.py -q --junitxml=${REPORT_DIR}/ssh.xml"
      }
    }


    stage('live: IKE responder') {
      // The IKE scanner has never run against a responder in any lane. GitHub
      // CI and the unit stage above both pass --ignore=tests/ike_lab, and that
      // suite needs the pinned strongSwan lab from #570, which is
      // unprovisioned. #1019 records the guard passing the suite on a loopback
      // reflection, which is how an absent lab reads as six failures.
      //
      // A public IKEv2 endpoint closes the gap with no lab: it answers v2 and
      // rejects both v1 modes, so one scan reaches responder-detected,
      // proposal-rejected, classical key exchange and weak group. The target is
      // a parameter and the suite skips when it is empty, so this node probes
      // only an endpoint its operator named.
      steps {
        script {
          if (!env.QUREDDY_IKE_PUBLIC_TARGET?.trim()) {
            echo 'IKE_PUBLIC_TARGET is not set; skipping the IKE responder stage'
            return
          }
          sh "uv run --locked pytest tests/live/test_live_ike_public.py -q --junitxml=${REPORT_DIR}/ike.xml"
        }
      }
    }


    stage('live: wallet accounts') {
      // Bitcoin, Litecoin and Ethereum against live indexers. The unit lane
      // cannot reach the chain lane at all, so every finding this suite asserts
      // exists only here: recovered key bytes, the signing-defect scan, the
      // coverage bound, and the indexer certificate.
      steps {
        sh "uv run --locked pytest tests/live/test_live_wallet.py tests/live/test_live_wallet_contract.py -q --junitxml=${REPORT_DIR}/wallet.xml"
      }
    }


    stage('live: CLI contract, every scheme') {
      // Four of the live files call the scanner in-process, which proves the
      // scanner and skips what the CLI owns: argument parsing, the exit-code
      // contract, and --output-dir writing the bundle. It also compares the
      // four projections against each other, so a renderer that drops or
      // invents a finding fails here instead of exiting zero.
      steps {
        sh "uv run --locked pytest tests/live/test_live_everything.py -q --junitxml=${REPORT_DIR}/cli.xml"
      }
    }


    stage('live: canonical targets') {
      steps {
        sh "uv run --locked pytest tests/live/test_live_targets.py -q --junitxml=${REPORT_DIR}/live.xml"
      }
    }


    stage('publish CBOMs') {
      // Every scan above proves a rating; this keeps the artifact so a rating
      // change is visible as a diff in the viewer rather than only as a pass or
      // fail in a build log. Non-blocking: the pipeline's verdict is the tests,
      // and a viewer that is down must not turn a green suite red.
      environment { QUREDDY_LEGACY_OPENSSL = "${LEGACY_OPENSSL_RESOLVED}" }
      steps {
        script {
          if (!env.CBOMKIT_API?.trim()) {
            echo 'CBOMKIT_API is not configured; skipping optional CBOM publication'
            return
          }
          def up = sh(returnStatus: true,
                      script: "curl -sS -o /dev/null --max-time 5 ${CBOMKIT_API}/api/v1/cbom/last/1")
          if (up != 0) {
            echo "CBOMkit unreachable at ${CBOMKIT_API}; skipping publish"
            return
          }
          sh '''
            set -eu
            sha=$(git rev-parse --short HEAD)
            stamp=$(date -u +%Y-%m-%dT%H%M%SZ)
            mkdir -p "$REPORT_DIR/cbom"
            for target in badssl.com:443 3des.badssl.com:443 rc4.badssl.com:443 null.badssl.com:443; do
              slug=$(echo "$target" | tr ':.' '--')
              out="$REPORT_DIR/cbom/$slug.cdx.json"
              # exit 2 is "findings present", the expected outcome for these hosts.
              uv run --locked qureddy scan tls "$target" --format cbom -o "$out" || true
              [ -s "$out" ] || { echo "no CBOM for $target" >&2; continue; }
              code=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 30 -X POST \
                "$CBOMKIT_API/api/v1/cbom/qureddy-$slug-$sha-$stamp" \
                -H 'Content-Type: application/json' --data-binary @"$out")
              echo "$target -> HTTP $code"
            done
            # Three chains, one grounded profile each. The wallet CBOM carries
            # the account key as related-crypto-material, which no other scanner
            # emits, so a change to that shape is visible here as a diff.
            for address in bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4 \
                           Ler4HNAEfwYhBmGXcFP2Po1NpRUEiK8km2 \
                           0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045; do
              slug=$(echo "$address" | cut -c1-12)
              # scan wallet takes --output-dir and rejects -o, so the run writes
              # its bundle and the CBOM is read out of it.
              run_dir="$REPORT_DIR/cbom/wallet-$slug"
              out="$run_dir/scan.cdx.json"
              mkdir -p "$run_dir"
              uv run --locked qureddy scan wallet "$address" --output-dir "$run_dir" || true
              [ -s "$out" ] || { echo "no CBOM for $address" >&2; continue; }
              code=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 30 -X POST \
                "$CBOMKIT_API/api/v1/cbom/qureddy-wallet-$slug-$sha-$stamp" \
                -H 'Content-Type: application/json' --data-binary @"$out")
              echo "$address -> HTTP $code"
            done
            uv run --locked qureddy scan ssh 127.0.0.1:22 --format cbom \
              -o "$REPORT_DIR/cbom/ssh-localhost.cdx.json" || true
            if [ -s "$REPORT_DIR/cbom/ssh-localhost.cdx.json" ]; then
              code=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 30 -X POST \
                "$CBOMKIT_API/api/v1/cbom/qureddy-ssh-localhost-$sha-$stamp" \
                -H 'Content-Type: application/json' --data-binary @"$REPORT_DIR/cbom/ssh-localhost.cdx.json")
              echo "ssh://127.0.0.1:22 -> HTTP $code"
            fi
          '''
        }
      }
    }


    stage('no skipped tests') {
      // A skipped test reports as a pass in most summaries. The badssl stages skip
      // themselves when the compatibility runtime is absent, which is the one way
      // this pipeline could go green while asserting nothing.
      steps {
        sh '''
          set -eu
          skipped=$(grep -ho 'skipped="[0-9]*"' "$REPORT_DIR"/*.xml \\
                    | grep -o '[0-9]*' | paste -sd+ - | bc)
          echo "skipped tests: ${skipped:-0}"
          [ "${skipped:-0}" -eq 0 ] || { echo "a test was skipped; see the reports" >&2; exit 1; }
        '''
      }
    }
  }

  post {
    always {
      junit allowEmptyResults: false, testResults: "${REPORT_DIR}/*.xml"
      archiveArtifacts artifacts: "${REPORT_DIR}/*.xml", allowEmptyArchive: false
    }
  }
}
