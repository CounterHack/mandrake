//! A data structure to configure address visibility.
//!
//! Basically, we need a way to show/hide different addresses, otherwise we get
//! potentially overwhelmed in libc and stuff. So we can either show or hide
//! certain addresses.
//!
//! When the harness loads code, it always loads it to `0x13370000`, so we
//! added a convenience function to always set that address.
//!
//! When an ELF is executed, by default everything is shown, but we implement
//! `clap` parsers so the user can pass in whatever they like on the
//! commandline.

use clap::Parser;
use clap_num::maybe_hex;

const DEFAULT_MASK: u64 = 0xFFFFFFFFFFFF0000;

#[derive(Parser, Debug)]
pub struct VisibilityConfiguration {
    /// Hide instructions that match this address (ANDed with the --hidden-mask)
    #[clap(long, parse(try_from_str=maybe_hex))]
    hidden_address:          Option<u64>,

    /// ANDed with the --hidden-address before comparing - by default, 0xFFFFFFFFFFFF0000
    #[clap(long, parse(try_from_str=maybe_hex))]
    hidden_mask:             Option<u64>,

    /// Only show instructions that match this address (ANDed with the --visible-mask)
    #[clap(long, parse(try_from_str=maybe_hex))]
    visible_address:         Option<u64>,

    /// ANDed with the --visible-address before comparing - by default, 0xFFFFFFFFFFFF0000
    #[clap(long, parse(try_from_str=maybe_hex))]
    visible_mask:            Option<u64>,
}

impl VisibilityConfiguration {
    /// Visibility settings when using the harness
    ///
    /// The harness always loads code to `0x13370000`.
    pub fn harness_visibility() -> Self {
        Self {
            hidden_address:          None,
            hidden_mask:             None,
            visible_address:         Some(0x13370000),
            visible_mask:            Some(0xFFFF0000),
        }
    }

    pub fn is_visible(&self, address: u64) -> bool {
        // Suppress addresses that match the hidden_address / hidden_mask, if set
        if let Some(hidden_address) = self.hidden_address {
            let mask = self.hidden_mask.unwrap_or(DEFAULT_MASK);

            if (address & mask) == hidden_address {
                return false;
            }
        }

        // Suppress addresses that don't match the visible_address / visible_mask
        if let Some(visible_address) = self.visible_address {
            let mask = self.visible_mask.unwrap_or(DEFAULT_MASK);

            if (address & mask) != visible_address {
                return false;
            }
        }

        true
    }
}
