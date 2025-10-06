#!/usr/bin/env node

import { MeshCorePacketDecoder } from './decoder/packet-decoder';
import { PayloadType, DeviceRole } from './types/enums';
import { getRouteTypeName, getPayloadTypeName, getDeviceRoleName } from './utils/enum-names';
import { AdvertPayload, GroupTextPayload, TracePayload } from './types/payloads';
import { Utils } from './index';
import { program } from 'commander';
import chalk from 'chalk';
import * as packageJson from '../package.json';

program
  .name('meshcore-decoder')
  .description('CLI tool for decoding MeshCore packets')
  .version(packageJson.version);

// Default decode command
program
  .command('decode', { isDefault: true })
  .description('Decode a MeshCore packet')
  .argument('<hex>', 'Hex string of the packet to decode')
  .option('-k, --key <keys...>', 'Channel secret keys for decryption (hex)')
  .option('-j, --json', 'Output as JSON instead of formatted text')
  .option('-s, --structure', 'Show detailed packet structure analysis')
  .action(async (hex: string, options: any) => {
    try {
      // Clean up hex input
      const cleanHex = hex.replace(/\s+/g, '').replace(/^0x/i, '');
      
      // Create key store if keys provided
      let keyStore;
      if (options.key && options.key.length > 0) {
        keyStore = MeshCorePacketDecoder.createKeyStore({
          channelSecrets: options.key
        });
      }
      
      // Decode packet with signature verification
      const packet = await MeshCorePacketDecoder.decodeWithVerification(cleanHex, { keyStore });
      
      if (options.json) {
        // JSON output
        if (options.structure) {
          const structure = await MeshCorePacketDecoder.analyzeStructureWithVerification(cleanHex, { keyStore });
          console.log(JSON.stringify({ packet, structure }, null, 2));
        } else {
          console.log(JSON.stringify(packet, null, 2));
        }
      } else {
        // Formatted output
        console.log(chalk.cyan('=== MeshCore Packet Analysis ===\n'));
        
        if (!packet.isValid) {
          console.log(chalk.red('❌ Invalid Packet'));
          if (packet.errors) {
            packet.errors.forEach(error => console.log(chalk.red(`   ${error}`)));
          }
        } else {
          console.log(chalk.green('✅ Valid Packet'));
        }
        
        console.log(`${chalk.bold('Message Hash:')} ${packet.messageHash}`);
        console.log(`${chalk.bold('Route Type:')} ${getRouteTypeName(packet.routeType)}`);
        console.log(`${chalk.bold('Payload Type:')} ${getPayloadTypeName(packet.payloadType)}`);
        console.log(`${chalk.bold('Total Bytes:')} ${packet.totalBytes}`);
        
        if (packet.path && packet.path.length > 0) {
          console.log(`${chalk.bold('Path:')} ${packet.path.join(' → ')}`);
        }
        
        // Show payload details (even for invalid packets)
        if (packet.payload.decoded) {
          console.log(chalk.cyan('\n=== Payload Details ==='));
          showPayloadDetails(packet.payload.decoded);
        }
        
        // Exit with error code if packet is invalid
        if (!packet.isValid) {
          process.exit(1);
        }
        
        // Show structure if requested
        if (options.structure) {
          const structure = await MeshCorePacketDecoder.analyzeStructureWithVerification(cleanHex, { keyStore });
          console.log(chalk.cyan('\n=== Packet Structure ==='));
          
          console.log(chalk.yellow('\nMain Segments:'));
          structure.segments.forEach((seg, i) => {
            console.log(`${i + 1}. ${chalk.bold(seg.name)} (bytes ${seg.startByte}-${seg.endByte}): ${seg.value}`);
            if (seg.description) {
              console.log(`   ${chalk.dim(seg.description)}`);
            }
          });
          
          if (structure.payload.segments.length > 0) {
            console.log(chalk.yellow('\nPayload Segments:'));
            structure.payload.segments.forEach((seg, i) => {
              console.log(`${i + 1}. ${chalk.bold(seg.name)} (bytes ${seg.startByte}-${seg.endByte}): ${seg.value}`);
              console.log(`   ${chalk.dim(seg.description)}`);
            });
          }
        }
      }
    } catch (error) {
      console.error(chalk.red('Error:'), (error as Error).message);
      process.exit(1);
    }
  });

function showPayloadDetails(payload: any): void {
  switch (payload.type) {
    case PayloadType.Advert:
      const advert = payload as AdvertPayload;
      console.log(`${chalk.bold('Device Role:')} ${getDeviceRoleName(advert.appData.deviceRole)}`);
      if (advert.appData.name) {
        console.log(`${chalk.bold('Device Name:')} ${advert.appData.name}`);
      }
      if (advert.appData.location) {
        console.log(`${chalk.bold('Location:')} ${advert.appData.location.latitude}, ${advert.appData.location.longitude}`);
      }
      console.log(`${chalk.bold('Timestamp:')} ${new Date(advert.timestamp * 1000).toISOString()}`);
      
      // Show signature verification status
      if (advert.signatureValid !== undefined) {
        if (advert.signatureValid) {
          console.log(`${chalk.bold('Signature:')} ${chalk.green('✅ Valid Ed25519 signature')}`);
        } else {
          console.log(`${chalk.bold('Signature:')} ${chalk.red('❌ Invalid Ed25519 signature')}`);
          if (advert.signatureError) {
            console.log(`${chalk.bold('Error:')} ${chalk.red(advert.signatureError)}`);
          }
        }
      } else {
        console.log(`${chalk.bold('Signature:')} ${chalk.yellow('⚠️ Not verified (use async verification)')}`);
      }
      break;
      
    case PayloadType.GroupText:
      const groupText = payload as GroupTextPayload;
      console.log(`${chalk.bold('Channel Hash:')} ${groupText.channelHash}`);
      if (groupText.decrypted) {
        console.log(chalk.green('🔓 Decrypted Message:'));
        if (groupText.decrypted.sender) {
          console.log(`${chalk.bold('Sender:')} ${groupText.decrypted.sender}`);
        }
        console.log(`${chalk.bold('Message:')} ${groupText.decrypted.message}`);
        console.log(`${chalk.bold('Timestamp:')} ${new Date(groupText.decrypted.timestamp * 1000).toISOString()}`);
      } else {
        console.log(chalk.yellow('🔒 Encrypted (no key available)'));
        console.log(`${chalk.bold('Ciphertext:')} ${groupText.ciphertext.substring(0, 32)}...`);
      }
      break;
      
    case PayloadType.Trace:
      const trace = payload as TracePayload;
      console.log(`${chalk.bold('Trace Tag:')} ${trace.traceTag}`);
      console.log(`${chalk.bold('Auth Code:')} ${trace.authCode}`);
      if (trace.snrValues && trace.snrValues.length > 0) {
        console.log(`${chalk.bold('SNR Values:')} ${trace.snrValues.map(snr => `${snr.toFixed(1)}dB`).join(', ')}`);
      }
      break;
      
    default:
      console.log(`${chalk.bold('Type:')} ${getPayloadTypeName(payload.type)}`);
      console.log(`${chalk.bold('Valid:')} ${payload.isValid ? '✅' : '❌'}`);
  }
}

// Add key derivation command
program
  .command('derive-key')
  .description('Derive Ed25519 public key from MeshCore private key')
  .argument('<private-key>', '64-byte private key in hex format')
  .option('-v, --validate <public-key>', 'Validate against expected public key')
  .option('-j, --json', 'Output as JSON')
  .action(async (privateKeyHex: string, options: any) => {
    try {
      // Clean up hex input
      const cleanPrivateKey = privateKeyHex.replace(/\s+/g, '').replace(/^0x/i, '');
      
      if (cleanPrivateKey.length !== 128) {
        console.error(chalk.red('❌ Error: Private key must be exactly 64 bytes (128 hex characters)'));
        process.exit(1);
      }
      
      if (options.json) {
        // JSON output
        const result: any = {
          privateKey: cleanPrivateKey,
          derivedPublicKey: await Utils.derivePublicKey(cleanPrivateKey)
        };
        
        if (options.validate) {
          const cleanExpectedKey = options.validate.replace(/\s+/g, '').replace(/^0x/i, '');
          result.expectedPublicKey = cleanExpectedKey;
          result.isValid = await Utils.validateKeyPair(cleanPrivateKey, cleanExpectedKey);
          result.match = result.derivedPublicKey.toLowerCase() === cleanExpectedKey.toLowerCase();
        }
        
        console.log(JSON.stringify(result, null, 2));
      } else {
        // Formatted output
        console.log(chalk.cyan('=== MeshCore Ed25519 Key Derivation ===\n'));
        
        console.log(chalk.bold('Private Key (64 bytes):'));
        console.log(chalk.gray(cleanPrivateKey));
        console.log();
        
        console.log(chalk.bold('Derived Public Key (32 bytes):'));
        const derivedKey = await Utils.derivePublicKey(cleanPrivateKey);
        console.log(chalk.green(derivedKey));
        console.log();
        
        if (options.validate) {
          const cleanExpectedKey = options.validate.replace(/\s+/g, '').replace(/^0x/i, '');
          console.log(chalk.bold('Expected Public Key:'));
          console.log(chalk.gray(cleanExpectedKey));
          console.log();
          
          const match = derivedKey.toLowerCase() === cleanExpectedKey.toLowerCase();
          console.log(chalk.bold('Validation:'));
          console.log(match ? chalk.green('Keys match') : chalk.red('Keys do not match'));
          
          if (!match) {
            process.exit(1);
          }
        }
        
        console.log(chalk.green('Key derivation completed successfully'));
      }
      
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      if (options.json) {
        console.log(JSON.stringify({ error: errorMessage }, null, 2));
      } else {
        console.error(chalk.red(`Error: ${errorMessage}`));
      }
      process.exit(1);
    }
  });

// Add auth-token command
program
  .command('auth-token')
  .description('Generate JWT authentication token signed with Ed25519 private key')
  .argument('<public-key>', '32-byte public key in hex format')
  .argument('<private-key>', '64-byte private key in hex format')
  .option('-e, --exp <seconds>', 'Token expiration in seconds from now (default: 86400 = 24 hours)', '86400')
  .option('-c, --claims <json>', 'Additional claims as JSON object (e.g., \'{"aud":"mqtt.example.com","sub":"device-123"}\')')
  .option('-j, --json', 'Output as JSON')
  .action(async (publicKeyHex: string, privateKeyHex: string, options: any) => {
    try {
      const { createAuthToken } = await import('./utils/auth-token');
      
      // Clean up hex inputs
      const cleanPublicKey = publicKeyHex.replace(/\s+/g, '').replace(/^0x/i, '');
      const cleanPrivateKey = privateKeyHex.replace(/\s+/g, '').replace(/^0x/i, '');
      
      if (cleanPublicKey.length !== 64) {
        console.error(chalk.red('❌ Error: Public key must be exactly 32 bytes (64 hex characters)'));
        process.exit(1);
      }
      
      if (cleanPrivateKey.length !== 128) {
        console.error(chalk.red('❌ Error: Private key must be exactly 64 bytes (128 hex characters)'));
        process.exit(1);
      }
      
      const expSeconds = parseInt(options.exp);
      const iat = Math.floor(Date.now() / 1000);
      const exp = iat + expSeconds;
      
      const payload: any = {
        publicKey: cleanPublicKey.toUpperCase(),
        iat,
        exp
      };
      
      // Parse and merge additional claims if provided
      if (options.claims) {
        try {
          const additionalClaims = JSON.parse(options.claims);
          Object.assign(payload, additionalClaims);
        } catch (e) {
          console.error(chalk.red('❌ Error: Invalid JSON in --claims option'));
          process.exit(1);
        }
      }
      
      const token = await createAuthToken(
        payload,
        cleanPrivateKey,
        cleanPublicKey.toUpperCase()
      );
      
      if (options.json) {
        console.log(JSON.stringify({
          token,
          payload
        }, null, 2));
      } else {
        console.log(token);
      }
      
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      if (options.json) {
        console.log(JSON.stringify({ error: errorMessage }, null, 2));
      } else {
        console.error(chalk.red(`Error: ${errorMessage}`));
      }
      process.exit(1);
    }
  });

// Add verify-token command
program
  .command('verify-token')
  .description('Verify JWT authentication token')
  .argument('<token>', 'JWT token to verify')
  .option('-p, --public-key <key>', 'Expected public key in hex format (optional)')
  .option('-j, --json', 'Output as JSON')
  .action(async (token: string, options: any) => {
    try {
      const { verifyAuthToken } = await import('./utils/auth-token');
      
      const cleanToken = token.trim();
      let expectedPublicKey: string | undefined;
      
      if (options.publicKey) {
        const cleanKey = options.publicKey.replace(/\s+/g, '').replace(/^0x/i, '').toUpperCase();
        if (cleanKey.length !== 64) {
          console.error(chalk.red('❌ Error: Public key must be exactly 32 bytes (64 hex characters)'));
          process.exit(1);
        }
        expectedPublicKey = cleanKey;
      }
      
      const payload = await verifyAuthToken(cleanToken, expectedPublicKey);
      
      if (payload) {
        const now = Math.floor(Date.now() / 1000);
        const isExpired = payload.exp && now > payload.exp;
        const timeToExpiry = payload.exp ? payload.exp - now : null;
        
        if (options.json) {
          console.log(JSON.stringify({
            valid: true,
            expired: isExpired,
            payload,
            timeToExpiry
          }, null, 2));
        } else {
          console.log(chalk.green('✅ Token is valid'));
          console.log(chalk.cyan('\nPayload:'));
          console.log(`  Public Key: ${payload.publicKey}`);
          console.log(`  Issued At:  ${new Date(payload.iat * 1000).toISOString()} (${payload.iat})`);
          if (payload.exp) {
            console.log(`  Expires At: ${new Date(payload.exp * 1000).toISOString()} (${payload.exp})`);
            if (isExpired) {
              console.log(chalk.red(`  Status:     EXPIRED`));
            } else {
              console.log(chalk.green(`  Status:     Valid for ${timeToExpiry} more seconds`));
            }
          }
          
          // Show any additional claims
          const standardClaims = ['publicKey', 'iat', 'exp'];
          const customClaims = Object.keys(payload).filter(k => !standardClaims.includes(k));
          if (customClaims.length > 0) {
            console.log(chalk.cyan('\nCustom Claims:'));
            customClaims.forEach(key => {
              console.log(`  ${key}: ${JSON.stringify(payload[key])}`);
            });
          }
        }
      } else {
        if (options.json) {
          console.log(JSON.stringify({
            valid: false,
            error: 'Token verification failed'
          }, null, 2));
        } else {
          console.error(chalk.red('❌ Token verification failed'));
          console.error(chalk.yellow('Possible reasons:'));
          console.error('  - Invalid signature');
          console.error('  - Token format is incorrect');
          console.error('  - Public key mismatch (if --public-key was provided)');
        }
        process.exit(1);
      }
      
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      if (options.json) {
        console.log(JSON.stringify({ valid: false, error: errorMessage }, null, 2));
      } else {
        console.error(chalk.red(`Error: ${errorMessage}`));
      }
      process.exit(1);
    }
  });

program.parse();
