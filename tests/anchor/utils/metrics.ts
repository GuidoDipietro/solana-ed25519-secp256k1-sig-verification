import * as anchor from '@coral-xyz/anchor';

export async function sendAndLogMetrics(
    connection: anchor.web3.Connection,
    tx: anchor.web3.Transaction,
    label?: string
): Promise<string> {
    const signature = await connection.sendRawTransaction(tx.serialize());
    
    // Wait for confirmation
    await connection.confirmTransaction(signature, 'confirmed');
    
    // Fetch transaction details
    const txDetails = await connection.getTransaction(signature, {
        maxSupportedTransactionVersion: 0,
        commitment: 'confirmed'
    });
    
    // Log metrics
    if (txDetails && txDetails.meta) {
        console.log(`\n  📊 Transaction Metrics${label ? ` (${label})` : ''}:`);
        console.log(`    • Compute Units: ${txDetails.meta.computeUnitsConsumed?.toLocaleString() || 'N/A'}`);
        console.log(`    • Fee: ${txDetails.meta.fee.toLocaleString()} lamports`);
        console.log(`    • Transaction Size: ${tx.serialize().length} bytes`);
        console.log(`    • Instructions: ${tx.instructions.length}`);
    }
    
    return signature;
}
