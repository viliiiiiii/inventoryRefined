<?php
// includes/inventory_modals.php
?>

<!-- Add Item Modal -->
<div class="modal fade" id="addItemModal" tabindex="-1">
    <div class="modal-dialog modal-lg">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title">Add New Item</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
            </div>
            <form method="post">
                <div class="modal-body">
                    <div class="row g-3">
                        <div class="col-md-6">
                            <label class="form-label">Item Name *</label>
                            <input type="text" class="form-control" name="name" required 
                                   placeholder="e.g., A4 Paper Pack">
                        </div>
                        <div class="col-md-6">
                            <label class="form-label">SKU</label>
                            <input type="text" class="form-control" name="sku" 
                                   placeholder="Optional SKU">
                        </div>
                        <div class="col-md-4">
                            <label class="form-label">Initial Quantity</label>
                            <input type="number" class="form-control" name="quantity" 
                                   min="0" value="0">
                        </div>
                        <div class="col-md-4">
                            <label class="form-label">Minimum Stock</label>
                            <input type="number" class="form-control" name="min_stock" 
                                   min="0" value="0">
                        </div>
                        <div class="col-md-4">
                            <label class="form-label">Location</label>
                            <input type="text" class="form-control" name="location" 
                                   placeholder="Aisle, Shelf, etc.">
                        </div>
                        <?php if ($isRoot): ?>
                        <div class="col-12">
                            <label class="form-label">Sector</label>
                            <select class="form-select" name="sector_id">
                                <option value="">Unassigned</option>
                                <?php foreach ($sectorOptions as $sector): ?>
                                    <option value="<?php echo $sector['id']; ?>">
                                        <?php echo htmlspecialchars($sector['name']); ?>
                                    </option>
                                <?php endforeach; ?>
                            </select>
                        </div>
                        <?php endif; ?>
                    </div>
                </div>
                <div class="modal-footer">
                    <input type="hidden" name="action" value="create_item">
                    <input type="hidden" name="<?php echo CSRF_TOKEN_NAME; ?>" value="<?php echo csrf_token(); ?>">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                    <button type="submit" class="btn btn-primary">Add Item</button>
                </div>
            </form>
        </div>
    </div>
</div>

<!-- Bulk Add Modal -->
<div class="modal fade" id="bulkAddModal" tabindex="-1">
    <div class="modal-dialog">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title">Bulk Add Items</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
            </div>
            <form method="post" enctype="multipart/form-data">
                <div class="modal-body">
                    <div class="alert alert-info">
                        <h6>CSV Format Required:</h6>
                        <code>name,sku,quantity,min_stock,location,sector_id</code>
                        <p class="mb-0 mt-2 small">Download <a href="/templates/inventory_template.csv">template</a></p>
                    </div>
                    
                    <div class="mb-3">
                        <label class="form-label">CSV File</label>
                        <input type="file" class="form-control" name="csv_file" 
                               accept=".csv" required>
                    </div>
                </div>
                <div class="modal-footer">
                    <input type="hidden" name="action" value="bulk_add_items">
                    <input type="hidden" name="<?php echo CSRF_TOKEN_NAME; ?>" value="<?php echo csrf_token(); ?>">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                    <button type="submit" class="btn btn-primary">Upload & Process</button>
                </div>
            </form>
        </div>
    </div>
</div>

<!-- Bulk Move Modal -->
<div class="modal fade" id="bulkMoveModal" tabindex="-1">
    <div class="modal-dialog">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title">Bulk Stock Movement</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
            </div>
            <form method="post" enctype="multipart/form-data">
                <div class="modal-body">
                    <div class="alert alert-info">
                        <h6>CSV Format Required:</h6>
                        <code>item_id,direction,amount,reason,target_sector_id,generate_paper</code>
                        <ul class="small mb-0 mt-2">
                            <li><strong>direction:</strong> 'in' or 'out'</li>
                            <li><strong>generate_paper:</strong> 1 or 0</li>
                        </ul>
                    </div>
                    
                    <div class="mb-3">
                        <label class="form-label">CSV File</label>
                        <input type="file" class="form-control" name="csv_file" 
                               accept=".csv" required>
                    </div>
                </div>
                <div class="modal-footer">
                    <input type="hidden" name="action" value="bulk_move_stock">
                    <input type="hidden" name="<?php echo CSRF_TOKEN_NAME; ?>" value="<?php echo csrf_token(); ?>">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                    <button type="submit" class="btn btn-primary">Upload & Process</button>
                </div>
            </form>
        </div>
    </div>
</div>

<!-- Edit Item Modal -->
<div class="modal fade" id="editItemModal" tabindex="-1">
    <div class="modal-dialog modal-lg">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title">Edit Item</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
            </div>
            <form method="post" id="editItemForm">
                <div class="modal-body">
                    <div id="editItemContent">
                        <!-- Content will be loaded via AJAX -->
                        <div class="text-center py-4">
                            <div class="spinner-border" role="status">
                                <span class="visually-hidden">Loading...</span>
                            </div>
                        </div>
                    </div>
                </div>
                <div class="modal-footer">
                    <input type="hidden" name="action" value="update_item">
                    <input type="hidden" name="item_id" id="editItemId">
                    <input type="hidden" name="<?php echo CSRF_TOKEN_NAME; ?>" value="<?php echo csrf_token(); ?>">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                    <button type="submit" class="btn btn-primary">Update Item</button>
                </div>
            </form>
        </div>
    </div>
</div>