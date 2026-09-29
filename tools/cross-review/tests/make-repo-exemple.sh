#!/usr/bin/env bash
# Crée un dépôt git jetable avec un commit initial propre et des
# modifications non commitées volontairement à problèmes (faille, secrets
# en dur), pour servir de fixture à `cross-review.py collect --mode code`.
#
# Sûreté : ce script ne supprime jamais rien en dehors de $TMPDIR, et
# seulement le dossier cross-review-repo-exemple qu'il gère lui-même.

set -euo pipefail

TMPDIR="${TMPDIR:-/tmp}"
REPO_DIR="${TMPDIR%/}/cross-review-repo-exemple"

if [ -d "$REPO_DIR" ]; then
    case "$REPO_DIR" in
        "${TMPDIR%/}"/*)
            rm -rf "$REPO_DIR"
            ;;
        *)
            echo "refus : $REPO_DIR n'est pas sous $TMPDIR, abandon." >&2
            exit 1
            ;;
    esac
fi

mkdir -p "$REPO_DIR/wp-content/plugins/demo-temoignages/assets"

git -C "$REPO_DIR" init -q
git -C "$REPO_DIR" config user.name "Cross Review Test"
git -C "$REPO_DIR" config user.email "test@example.invalid"

# --- Commit initial : état propre --------------------------------------

cat > "$REPO_DIR/wp-content/plugins/demo-temoignages/demo-temoignages.php" <<'PHP'
<?php
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Plugin Name: DEMO Témoignages
 * Description: Gestion des témoignages clients.
 */

function demo_temoignages_get_count() {
    $counts = wp_count_posts( 'temoignage' );
    return isset( $counts->publish ) ? (int) $counts->publish : 0;
}

add_action( 'init', 'demo_temoignages_register_cpt' );

function demo_temoignages_register_cpt() {
    register_post_type(
        'temoignage',
        array(
            'label'    => 'Témoignages',
            'public'   => false,
            'show_ui'  => true,
            'supports' => array( 'title', 'editor' ),
        )
    );
}
PHP

cat > "$REPO_DIR/wp-config.php" <<'PHP'
<?php
define( 'DB_NAME', 'exemple' );
define( 'DB_USER', 'exemple' );
define( 'DB_PASSWORD', 'FAUX-SECRET-TEST-wpconfig-init' );
define( 'DB_HOST', 'localhost' );
PHP

git -C "$REPO_DIR" add -A
git -C "$REPO_DIR" commit -q -m "État initial : CPT témoignages"

# --- Modifications non commitées : problèmes volontaires ---------------

cat > "$REPO_DIR/wp-content/plugins/demo-temoignages/demo-temoignages.php" <<'PHP'
<?php
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Plugin Name: DEMO Témoignages
 * Description: Gestion des témoignages clients.
 */

define( 'DEMO_API_TOKEN', 'FAUX-SECRET-TEST-1234567890' );

$openrouter = 'sk-or-v1-FAUXSECRETTEST00000000000000000000';

function demo_temoignages_get_count() {
    $counts = wp_count_posts( 'temoignage' );
    return isset( $counts->publish ) ? (int) $counts->publish : 0;
}

add_action( 'init', 'demo_temoignages_register_cpt' );

function demo_temoignages_register_cpt() {
    register_post_type(
        'temoignage',
        array(
            'label'    => 'Témoignages',
            'public'   => false,
            'show_ui'  => true,
            'supports' => array( 'title', 'editor' ),
        )
    );
}

// Recherche par mot-clé, affichée directement dans la page.
function demo_temoignages_search_notice() {
    if ( isset( $_GET['q'] ) ) {
        echo 'Recherche : ' . $_GET['q'];
    }
}
add_action( 'admin_notices', 'demo_temoignages_search_notice' );

// Suppression d'un témoignage par id, sans requête préparée.
function demo_temoignages_delete_raw( $id ) {
    global $wpdb;
    return $wpdb->query( "DELETE FROM {$wpdb->posts} WHERE id = $id" );
}

// Endpoint AJAX public du compteur, sans nonce ni vérification de capacité.
add_action( 'wp_ajax_nopriv_demo_temoignages_count', 'demo_temoignages_ajax_count' );
add_action( 'wp_ajax_demo_temoignages_count', 'demo_temoignages_ajax_count' );

function demo_temoignages_ajax_count() {
    wp_send_json_success( array( 'count' => demo_temoignages_get_count() ) );
}
PHP

cat > "$REPO_DIR/wp-config.php" <<'PHP'
<?php
define( 'DB_NAME', 'exemple' );
define( 'DB_USER', 'exemple' );
define( 'DB_PASSWORD', 'FAUX-SECRET-TEST-wpconfig' );
define( 'DB_HOST', 'localhost' );
PHP

cat > "$REPO_DIR/wp-content/plugins/demo-temoignages/assets/temoignages.js" <<'JS'
function initTemoignagesCounter() {
    var el = document.querySelector( '.demo-temoignages-count' );
    if ( ! el ) {
        return;
    }
    // Bug : l'écouteur est rajouté à chaque appel de la fonction, jamais retiré.
    el.addEventListener( 'click', function () {
        fetch( '/wp-admin/admin-ajax.php?action=demo_temoignages_count' )
            .then( function ( r ) { return r.json(); } )
            .then( function ( data ) { el.textContent = data.data.count; } );
    } );
}

document.addEventListener( 'DOMContentLoaded', initTemoignagesCounter );
JS

cat > "$REPO_DIR/.env" <<'ENV'
DB_PASSWORD=FAUX-SECRET-TEST-env
ENV

cat > "$REPO_DIR/dump.sql" <<'SQL'
INSERT INTO wp_options (option_name, option_value) VALUES ('demo_legacy_secret', 'FAUX-SECRET-TEST-sql');
SQL

echo "$REPO_DIR"
