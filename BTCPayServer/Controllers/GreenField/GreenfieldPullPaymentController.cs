#nullable enable
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using BTCPayServer.Abstractions.Constants;
using BTCPayServer.Client;
using BTCPayServer.Client.Models;
using BTCPayServer.Data;
using BTCPayServer.HostedServices;
using BTCPayServer.Payments;
using BTCPayServer.Services;
using BTCPayServer.Services.Rates;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Cors;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;
using Microsoft.EntityFrameworkCore;

// kk start
using BTCPayServer;
using BTCPayServer.Abstractions.Extensions;
using BTCPayServer.Abstractions.Models;
using BTCPayServer.ModelBinders;
using BTCPayServer.Models;
using BTCPayServer.Models.StoreViewModels;
using BTCPayServer.Models.WalletViewModels;
using BTCPayServer.Services.Labels;
using BTCPayServer.Services.Wallets;
using Microsoft.AspNetCore.Identity;
using NBitcoin;
using BTCPayServer.BIP78.Sender;
using BTCPayServer.Payments.PayJoin;
using BTCPayServer.Payments.PayJoin.Sender;
using BTCPayServer.Services.Stores;
using NBitcoin.Payment;
using NBXplorer;
using NBXplorer.DerivationStrategy;
using NBXplorer.Models;

using System.Net.Http;
using Newtonsoft.Json.Linq;
// kk end

namespace BTCPayServer.Controllers.Greenfield
{
    [ApiController]
    [Authorize(AuthenticationSchemes = AuthenticationSchemes.Greenfield)]
    [EnableCors(CorsPolicies.All)]
    public class GreenfieldPullPaymentController : ControllerBase
    {
        private readonly PullPaymentHostedService _pullPaymentService;
        private readonly LinkGenerator _linkGenerator;
        private readonly ApplicationDbContextFactory _dbContextFactory;
        private readonly CurrencyNameTable _currencyNameTable;
        private readonly BTCPayNetworkJsonSerializerSettings _serializerSettings;
        private readonly BTCPayNetworkProvider _networkProvider;
        private readonly IEnumerable<IPayoutHandler> _payoutHandlers;
        private readonly StoreRepository _storeRepository;
        private readonly ExplorerClientProvider _explorerClientProvider;

        public GreenfieldPullPaymentController(PullPaymentHostedService pullPaymentService,
            LinkGenerator linkGenerator,
            ApplicationDbContextFactory dbContextFactory,
            CurrencyNameTable currencyNameTable,
            Services.BTCPayNetworkJsonSerializerSettings serializerSettings,
            BTCPayNetworkProvider networkProvider,
            IEnumerable<IPayoutHandler> payoutHandlers,
            StoreRepository storeRepository,
            ExplorerClientProvider explorerProvider)
        {
            _pullPaymentService = pullPaymentService;
            _linkGenerator = linkGenerator;
            _dbContextFactory = dbContextFactory;
            _currencyNameTable = currencyNameTable;
            _serializerSettings = serializerSettings;
            _networkProvider = networkProvider;
            _payoutHandlers = payoutHandlers;
            // kk start
            _storeRepository = storeRepository;            
            _explorerClientProvider = explorerProvider;
            // kk end
        }

        [HttpGet("~/api/v1/stores/{storeId}/pull-payments")]
        [Authorize(Policy = Policies.CanManagePullPayments, AuthenticationSchemes = AuthenticationSchemes.Greenfield)]
        public async Task<IActionResult> GetPullPayments(string storeId, bool includeArchived = false)
        {
            using var ctx = _dbContextFactory.CreateContext();
            var pps = await ctx.PullPayments
                .Where(p => p.StoreId == storeId && (includeArchived || !p.Archived))
                .OrderByDescending(p => p.StartDate)
                .ToListAsync();
            return Ok(pps.Select(CreatePullPaymentData).ToArray());
        }

        [HttpPost("~/api/v1/stores/{storeId}/pull-payments")]
        [Authorize(Policy = Policies.CanManagePullPayments, AuthenticationSchemes = AuthenticationSchemes.Greenfield)]
        public async Task<IActionResult> CreatePullPayment(string storeId, CreatePullPaymentRequest request)
        {
            if (request is null)
            {
                ModelState.AddModelError(string.Empty, "Missing body");
                return this.CreateValidationError(ModelState);
            }
            if (request.Amount <= 0.0m)
            {
                ModelState.AddModelError(nameof(request.Amount), "The amount should more than 0.");
            }
            if (request.Name is String name && name.Length > 50)
            {
                ModelState.AddModelError(nameof(request.Name), "The name should be maximum 50 characters.");
            }
            if (request.Currency is String currency)
            {
                request.Currency = currency.ToUpperInvariant().Trim();
                if (_currencyNameTable.GetCurrencyData(request.Currency, false) is null)
                {
                    ModelState.AddModelError(nameof(request.Currency), "Invalid currency");
                }
            }
            else
            {
                ModelState.AddModelError(nameof(request.Currency), "This field is required");
            }
            if (request.ExpiresAt is DateTimeOffset expires && request.StartsAt is DateTimeOffset start && expires < start)
            {
                ModelState.AddModelError(nameof(request.ExpiresAt), $"expiresAt should be higher than startAt");
            }
            if (request.Period <= TimeSpan.Zero)
            {
                ModelState.AddModelError(nameof(request.Period), $"The period should be positive");
            }
            PaymentMethodId?[]? paymentMethods = null;
            if (request.PaymentMethods is { } paymentMethodsStr)
            {
                paymentMethods = paymentMethodsStr.Select(s =>
                {
                    PaymentMethodId.TryParse(s, out var pmi);
                    return pmi;
                }).ToArray();
                var supported = (await _payoutHandlers.GetSupportedPaymentMethods(HttpContext.GetStoreData())).ToArray();
                for (int i = 0; i < paymentMethods.Length; i++)
                {
                    if (!supported.Contains(paymentMethods[i]))
                    {
                        request.AddModelError(paymentRequest => paymentRequest.PaymentMethods[i], "Invalid or unsupported payment method", this);
                    }
                }
            }
            else
            {
                ModelState.AddModelError(nameof(request.PaymentMethods), "This field is required");
            }
            if (!ModelState.IsValid)
                return this.CreateValidationError(ModelState);
            var ppId = await _pullPaymentService.CreatePullPayment(new HostedServices.CreatePullPayment()
            {
                StartsAt = request.StartsAt,
                ExpiresAt = request.ExpiresAt,
                Period = request.Period,
                Name = request.Name,
                Amount = request.Amount,
                Currency = request.Currency,
                StoreId = storeId,
                PaymentMethodIds = paymentMethods
            });
            var pp = await _pullPaymentService.GetPullPayment(ppId, false);
            return this.Ok(CreatePullPaymentData(pp));
        }

        private Client.Models.PullPaymentData CreatePullPaymentData(Data.PullPaymentData pp)
        {
            var ppBlob = pp.GetBlob();
            return new BTCPayServer.Client.Models.PullPaymentData()
            {
                Id = pp.Id,
                StartsAt = pp.StartDate,
                ExpiresAt = pp.EndDate,
                Amount = ppBlob.Limit,
                Name = ppBlob.Name,
                Currency = ppBlob.Currency,
                Period = ppBlob.Period,
                Archived = pp.Archived,
                ViewLink = _linkGenerator.GetUriByAction(
                                nameof(UIPullPaymentController.ViewPullPayment),
                                "UIPullPayment",
                                new { pullPaymentId = pp.Id },
                                Request.Scheme,
                                Request.Host,
                                Request.PathBase)
            };
        }

        [HttpGet("~/api/v1/pull-payments/{pullPaymentId}")]
        [AllowAnonymous]
        public async Task<IActionResult> GetPullPayment(string pullPaymentId)
        {
            if (pullPaymentId is null)
                return PullPaymentNotFound();
            var pp = await _pullPaymentService.GetPullPayment(pullPaymentId, false);
            if (pp is null)
                return PullPaymentNotFound();
            return Ok(CreatePullPaymentData(pp));
        }

        [HttpGet("~/api/v1/pull-payments/{pullPaymentId}/payouts")]
        [AllowAnonymous]
        public async Task<IActionResult> GetPayouts(string pullPaymentId, bool includeCancelled = false)
        {
            if (pullPaymentId is null)
                return PullPaymentNotFound();
            var pp = await _pullPaymentService.GetPullPayment(pullPaymentId, true);
            if (pp is null)
                return PullPaymentNotFound();
            var payouts = pp.Payouts.Where(p => p.State != PayoutState.Cancelled || includeCancelled).ToList();
            var cd = _currencyNameTable.GetCurrencyData(pp.GetBlob().Currency, false);
            return base.Ok(payouts
                    .Select(p => ToModel(p, cd)).ToList());
        }

        [HttpGet("~/api/v1/pull-payments/{pullPaymentId}/payouts/{payoutId}")]
        [AllowAnonymous]
        public async Task<IActionResult> GetPayout(string pullPaymentId, string payoutId)
        {
            if (payoutId is null)
                return PayoutNotFound();
            await using var ctx = _dbContextFactory.CreateContext();
            var pp = await _pullPaymentService.GetPullPayment(pullPaymentId, true);
            if (pp is null)
                return PullPaymentNotFound();
            var payout = pp.Payouts.FirstOrDefault(p => p.Id == payoutId);
            if (payout is null)
                return PayoutNotFound();
            var cd = _currencyNameTable.GetCurrencyData(payout.PullPaymentData.GetBlob().Currency, false);
            return base.Ok(ToModel(payout, cd));
        }

        private Client.Models.PayoutData ToModel(Data.PayoutData p, CurrencyData cd)
        {
            var blob = p.GetBlob(_serializerSettings);
            var model = new Client.Models.PayoutData()
            {
                Id = p.Id,
                PullPaymentId = p.PullPaymentDataId,
                Date = p.Date,
                Amount = blob.Amount,
                PaymentMethodAmount = blob.CryptoAmount,
                Revision = blob.Revision,
                State = p.State
            };
            model.Destination = blob.Destination;
            model.PaymentMethod = p.PaymentMethodId;
            model.CryptoCode = p.GetPaymentMethodId().CryptoCode;
            return model;
        }

        [HttpPost("~/api/v1/pull-payments/{pullPaymentId}/payouts")]
        [AllowAnonymous]
        public async Task<IActionResult> CreatePayout(string pullPaymentId, CreatePayoutRequest request)
        {
            if (!PaymentMethodId.TryParse(request?.PaymentMethod, out var paymentMethodId))
            {
                ModelState.AddModelError(nameof(request.PaymentMethod), "Invalid payment method");
                return this.CreateValidationError(ModelState);
            }

            var payoutHandler = _payoutHandlers.FindPayoutHandler(paymentMethodId);
            if (payoutHandler is null)
            {
                ModelState.AddModelError(nameof(request.PaymentMethod), "Invalid payment method");
                return this.CreateValidationError(ModelState);
            }

            await using var ctx = _dbContextFactory.CreateContext();
            var pp = await ctx.PullPayments.FindAsync(pullPaymentId);
            if (pp is null)
                return PullPaymentNotFound();
            var ppBlob = pp.GetBlob();
            var destination = await payoutHandler.ParseClaimDestination(paymentMethodId, request!.Destination, true);
            if (destination.destination is null)
            {
                ModelState.AddModelError(nameof(request.Destination), destination.error ?? "The destination is invalid for the payment specified");
                return this.CreateValidationError(ModelState);
            }

            if (request.Amount is null && destination.destination.Amount != null)
            {
                request.Amount = destination.destination.Amount;
            }
            else if (request.Amount != null && destination.destination.Amount != null && request.Amount != destination.destination.Amount)
            {
                ModelState.AddModelError(nameof(request.Amount), $"Amount is implied in destination ({destination.destination.Amount}) that does not match the payout amount provided {request.Amount})");
                return this.CreateValidationError(ModelState);
            }
            if (request.Amount is { } v && (v < ppBlob.MinimumClaim || v == 0.0m))
            {
                ModelState.AddModelError(nameof(request.Amount), $"Amount too small (should be at least {ppBlob.MinimumClaim})");
                return this.CreateValidationError(ModelState);
            }
            var cd = _currencyNameTable.GetCurrencyData(pp.GetBlob().Currency, false);
            var result = await _pullPaymentService.Claim(new ClaimRequest()
            {
                Destination = destination.destination,
                PullPaymentId = pullPaymentId,
                Value = request.Amount,
                PaymentMethodId = paymentMethodId
            });
            switch (result.Result)
            {
                case ClaimRequest.ClaimResult.Ok:
                    break;
                case ClaimRequest.ClaimResult.Duplicate:
                    return this.CreateAPIError("duplicate-destination", ClaimRequest.GetErrorMessage(result.Result));
                case ClaimRequest.ClaimResult.Expired:
                    return this.CreateAPIError("expired", ClaimRequest.GetErrorMessage(result.Result));
                case ClaimRequest.ClaimResult.NotStarted:
                    return this.CreateAPIError("not-started", ClaimRequest.GetErrorMessage(result.Result));
                case ClaimRequest.ClaimResult.Archived:
                    return this.CreateAPIError("archived", ClaimRequest.GetErrorMessage(result.Result));
                case ClaimRequest.ClaimResult.Overdraft:
                    return this.CreateAPIError("overdraft", ClaimRequest.GetErrorMessage(result.Result));
                case ClaimRequest.ClaimResult.AmountTooLow:
                    return this.CreateAPIError("amount-too-low", ClaimRequest.GetErrorMessage(result.Result));
                case ClaimRequest.ClaimResult.PaymentMethodNotSupported:
                    return this.CreateAPIError("payment-method-not-supported", ClaimRequest.GetErrorMessage(result.Result));
                default:
                    throw new NotSupportedException("Unsupported ClaimResult");
            }
            return Ok(ToModel(result.PayoutData, cd));
        }

        [HttpDelete("~/api/v1/stores/{storeId}/pull-payments/{pullPaymentId}")]
        [Authorize(Policy = Policies.CanManagePullPayments, AuthenticationSchemes = AuthenticationSchemes.Greenfield)]
        public async Task<IActionResult> ArchivePullPayment(string storeId, string pullPaymentId)
        {
            using var ctx = _dbContextFactory.CreateContext();
            var pp = await ctx.PullPayments.FindAsync(pullPaymentId);
            if (pp is null || pp.StoreId != storeId)
                return PullPaymentNotFound();
            await _pullPaymentService.Cancel(new PullPaymentHostedService.CancelRequest(pullPaymentId));
            return Ok();
        }

        [HttpDelete("~/api/v1/stores/{storeId}/payouts/{payoutId}")]
        [Authorize(Policy = Policies.CanManagePullPayments, AuthenticationSchemes = AuthenticationSchemes.Greenfield)]
        public async Task<IActionResult> CancelPayout(string storeId, string payoutId)
        {
            using var ctx = _dbContextFactory.CreateContext();
            var payout = await ctx.Payouts.GetPayout(payoutId, storeId);
            if (payout is null)
                return PayoutNotFound();
            await _pullPaymentService.Cancel(new PullPaymentHostedService.CancelRequest(new[] { payoutId }));
            return Ok();
        }

        [HttpPost("~/api/v1/stores/{storeId}/payouts/{payoutId}")]
        [Authorize(Policy = Policies.CanManagePullPayments, AuthenticationSchemes = AuthenticationSchemes.Greenfield)]
        public async Task<IActionResult> ApprovePayout(string storeId, string payoutId, ApprovePayoutRequest approvePayoutRequest, CancellationToken cancellationToken = default)
        {
            using var ctx = _dbContextFactory.CreateContext();
            ctx.ChangeTracker.QueryTrackingBehavior = QueryTrackingBehavior.NoTracking;
            var revision = approvePayoutRequest?.Revision;
            if (revision is null)
            {
                ModelState.AddModelError(nameof(approvePayoutRequest.Revision), "The `revision` property is required");
            }
            if (!ModelState.IsValid)
                return this.CreateValidationError(ModelState);
            var payout = await ctx.Payouts.GetPayout(payoutId, storeId, true, true);
            if (payout is null)
                return PayoutNotFound();
            RateResult? rateResult = null;
            try
            {
                rateResult = await _pullPaymentService.GetRate(payout, approvePayoutRequest?.RateRule, cancellationToken);
                if (rateResult.BidAsk == null)
                {
                    return this.CreateAPIError("rate-unavailable", $"Rate unavailable: {rateResult.EvaluatedRule}");
                }
            }
            catch (FormatException)
            {
                ModelState.AddModelError(nameof(approvePayoutRequest.RateRule), "Invalid RateRule");
                return this.CreateValidationError(ModelState);
            }
            var ppBlob = payout.PullPaymentData.GetBlob();
            var cd = _currencyNameTable.GetCurrencyData(ppBlob.Currency, false);
            var result = await _pullPaymentService.Approve(new PullPaymentHostedService.PayoutApproval()
            {
                PayoutId = payoutId,
                Revision = revision!.Value,
                Rate = rateResult.BidAsk.Ask
            });
            var errorMessage = PullPaymentHostedService.PayoutApproval.GetErrorMessage(result);
            switch (result)
            {
                case PullPaymentHostedService.PayoutApproval.Result.Ok:
                    return Ok(ToModel(await ctx.Payouts.GetPayout(payoutId, storeId, true), cd));
                case PullPaymentHostedService.PayoutApproval.Result.InvalidState:
                    return this.CreateAPIError("invalid-state", errorMessage);
                case PullPaymentHostedService.PayoutApproval.Result.TooLowAmount:
                    return this.CreateAPIError("amount-too-low", errorMessage);
                case PullPaymentHostedService.PayoutApproval.Result.OldRevision:
                    return this.CreateAPIError("old-revision", errorMessage);
                case PullPaymentHostedService.PayoutApproval.Result.NotFound:
                    return PayoutNotFound();
                default:
                    throw new NotSupportedException();
            }
        }
        
        [HttpPost("~/api/v1/stores/{storeId}/payouts/{payoutId}/send_kk")]
        [Authorize(Policy = Policies.CanManagePullPayments, AuthenticationSchemes = AuthenticationSchemes.Greenfield)]
        public async Task<IActionResult> SendPayoutPayment_KK(string storeId, string payoutId, CreatePayoutRequest request)
        {
            /*
            // v2 wenn payout was created. Extract amount and destination from payoutId

            using var ctx = _dbContextFactory.CreateContext();
            var payout = await ctx.Payouts.GetPayout(payoutId, storeId);
            if (payout is null)
                return PayoutNotFound();

            var pp = await ctx.PullPayments.FindAsync(payout.PullPaymentDataId);
            if (pp is null)
                return PullPaymentNotFound();  

            // var destination = payout.Destination; // "bcrt1qr5d55lpfvlln6lxtuppgw5kwvjq26s8d9wy8n7"              
            // var amount = 0.001;
            */     

            var substractFees = true; // Gebühr vom gesendeten Wert abziehen und nicht extra für uns berechnen. In der Rückgabe beim ptsb Objekt steht welche Gebühr ggf. berechnet wird
            
            decimal feeSatoshiPerByte = 0;
            try {  
                string feeUrl = "https://bitcoinfees.earn.com/api/v1/fees/recommended";
                HttpClient clientFee = new HttpClient();
                string responseFee = await clientFee.GetStringAsync(feeUrl);
                dynamic dataFee = JObject.Parse(responseFee);      
                feeSatoshiPerByte = dataFee.hourFee;          
            } catch (Exception ex){
                feeSatoshiPerByte = 50;
            }


// kk tbd. check if parameters destination and amount  are valid
            var destination = request.Destination;           
            var amount = request.Amount.ToString();            

            // kk own
            var walletId = new WalletId(storeId, "BTC"); // CryptoCode "BTC"

            // kk copied source 1 use
            /******************** WalletSend() *******************/
            var network = _networkProvider.GetNetwork<BTCPayNetwork>(walletId?.CryptoCode); // CryptoCode "BTC"
            //var network = _networkProvider.GetNetwork<BTCPayNetwork>("BTC");
            if (network == null || network.ReadonlyWallet)
                return NotFound();

            //var store = HttpContext.GetStoreData(); // alternative method to get store (but is it always the store with the right storeID??)            
            var store = await _storeRepository.FindStore(walletId.StoreId);
            DerivationSchemeSettings derivationScheme = store?.GetDerivationSchemeSettings(_networkProvider, walletId.CryptoCode);   
            CreatePSBTResponse psbtResponse;
            
            try
            {   
                var cancellationToken = CancellationToken.None;            
                var noChange = false;
                
                // kk copied source 2 use   
                /******************** CreatePSBT() Start *******************/                             
                var nbx = _explorerClientProvider.GetExplorerClient(network);
                CreatePSBTRequest psbtRequest = new CreatePSBTRequest();
                var psbtDestination = new CreatePSBTDestination();
                 
                psbtRequest.Destinations.Add(psbtDestination);
                psbtDestination.Destination = BitcoinAddress.Create(destination, network.NBitcoinNetwork);;
                psbtDestination.Amount = amount;                
                psbtDestination.SubstractFees = substractFees; 

                if (network.SupportRBF)
                {               
                        //psbtRequest.RBF = true;  // AllowFeeBump??
                        psbtRequest.RBF = false;
                }

                psbtRequest.AlwaysIncludeNonWitnessUTXO = false;            
                psbtRequest.FeePreference = new FeePreference();            
                psbtRequest.FeePreference.ExplicitFeeRate = new FeeRate(feeSatoshiPerByte);           
                
                if (noChange)
                {
                    psbtRequest.ExplicitChangeAddress = psbtRequest.Destinations.First().Destination;
                }

                psbtResponse = (await nbx.CreatePSBTAsync(derivationScheme.AccountDerivation, psbtRequest, cancellationToken));
                if (psbtResponse == null)
                    throw new NotSupportedException("You need to update your version of NBXplorer");
                // Not supported by coldcard, remove when they do support it
                psbtResponse.PSBT.GlobalXPubs.Clear();
            }
            catch (NBXplorerException ex)
            {
                return this.CreateAPIError("psbterror", ex.Error.Message);
            } 
            catch (NotSupportedException)
            {
                return this.CreateAPIError("psbterror2", "NotSupportedException");
            }             
            catch (Exception ex){
                return this.CreateAPIError("psbterror3", ex.Message);
            }
            /******************** CreatePSBT() END *******************/

            var psbt = psbtResponse.PSBT;
            derivationScheme.RebaseKeyPaths(psbt);
            
            var signingContext = new SigningContextModel
            {
                PayJoinBIP21 = null,
                EnforceLowR = psbtResponse.Suggestions?.ShouldEnforceLowR,
                ChangeAddress = psbtResponse.ChangeAddress?.ToString()
            };

            // kk copied source 3 use  
            /******************** TryHandleSigningCommands() *******************/
            // SIGN TRANSACTION          
            var command = "nbx-seed";
            signingContext.PSBT = psbt.ToBase64();
            switch (command)
            {
                case "sign":
                    break;
                case "vault":
                    break;
                case "seed":
                    break;
                    //return SignWithSeed(walletId, signingContext);
                case "nbx-seed":                    
                    var canUseHotWallet = true;                    
                    if (canUseHotWallet)
                    {                        
                        if (derivationScheme.IsHotWallet)
                        {
                            var _extKey = await _explorerClientProvider.GetExplorerClient(network)
                                .GetMetadataAsync<string>(derivationScheme.AccountDerivation,
                                    WellknownMetadataKeys.MasterHDKey);                                     
                            /******************** TryHandleSigningCommands() END *******************/
                                                        
                            // kk copied source 4 use
                            /******************** SignWithSeed() Start *******************/                            
                            var viewModel = new SignWithSeedViewModel { SeedOrKey = _extKey, SigningContext = signingContext };
                            ExtKey extKey = viewModel.GetExtKey(network.NBitcoinNetwork);     
                            
                            if (!psbt.IsReadyToSign())
                            {
                                return this.CreateAPIError("psbtsignerror", "Error Signing 1");
                            }

                            ExtKey signingKey = null;
                            var settings = derivationScheme;
                            var signingKeySettings = settings.GetSigningAccountKeySettings();
                            if (signingKeySettings.RootFingerprint is null)
                                signingKeySettings.RootFingerprint = extKey.GetPublicKey().GetHDFingerPrint();

                            RootedKeyPath rootedKeyPath = signingKeySettings.GetRootedKeyPath();
                            if (rootedKeyPath == null)
                            {
                                return this.CreateAPIError("psbtsignerror", "Error Signing 2");
                                //  "The master fingerprint and/or account key path of your seed are not set in the wallet settings."
                            }
                            // The user gave the root key, let's try to rebase the PSBT, and derive the account private key
                            if (rootedKeyPath.MasterFingerprint == extKey.GetPublicKey().GetHDFingerPrint())
                            {
                                psbt.RebaseKeyPaths(signingKeySettings.AccountKey, rootedKeyPath);
                                signingKey = extKey.Derive(rootedKeyPath.KeyPath);
                            }
                            else
                            {
                                return this.CreateAPIError("psbtsignerror", "Error Signing 3");
                                // "The master fingerprint does not match the one set in your wallet settings. Probable causes are: wrong seed, wrong passphrase or wrong fingerprint in your wallet settings."
                            }

                            psbt.Settings.SigningOptions = new SigningOptions()
                            {
                                EnforceLowR = !(signingContext?.EnforceLowR is false)
                            };
                            var changed = psbt.PSBTChanged( () => psbt.SignAll(settings.AccountDerivation, signingKey, rootedKeyPath));
                            if (!changed)
                            {
                                // "Impossible to sign the transaction. Probable causes: Incorrect account key path in wallet settings or PSBT already signed."
                                return this.CreateAPIError("psbtsignerror", "Error Signing 4");                                
                            }
                            
                            signingContext.PSBT = psbt.ToBase64();
                            
                            var SigningKey = signingKey.GetWif(network.NBitcoinNetwork).ToString();
                            var SigningKeyPath = rootedKeyPath?.ToString();
                            var SigningContext = signingContext;
                            /******************** SignWithSeed() END *******************/

                            // kk own send results with fee info back to bot
                            var jsonRet = psbt.ToString();
                            var hexRet = psbt.ToHex();
                            // kk end

                            string[] retData = new string[2];
                            retData[0] = jsonRet;
                            retData[1] = hexRet;

                            return Ok(retData);  // v2 send/broadcast money with another API call                                  

                            // v1 send/broadcast money now
                            if (false) {
                                // kk copied source 5 use
                                /******************** FetchTransactionDetails() Start *******************/                            
                                if (!psbt.IsAllFinalized() && !psbt.TryFinalize(out var errors)) {
                                    return this.CreateAPIError("psbtsignerror", "Error Signing 5");                                
                                }                            
                                /******************** FetchTransactionDetails() END *******************/

                                // kk copied source 6 use
                                /******************** WalletPSBTReady() Start *******************/      
                                // BROADCAST TRANSACTION                     
                                var transaction = psbt.ExtractTransaction();
                                try
                                {
                                    var broadcastResult = await _explorerClientProvider.GetExplorerClient(network).BroadcastAsync(transaction);
                                    if (!broadcastResult.Success)
                                    {
                                        return this.CreateAPIError("psbtbroadcasterror", "Error Broadcast");
                                    }
                                }
                                catch (Exception ex)
                                {
                                    return this.CreateAPIError("psbtbroadcasterror", ex.Message);
                                }     
                                /******************** WalletPSBTReady() END *******************/                            

                                return Ok();                                             
                            }
                        }
                    }
                    
                    break;
            }
                     
            return this.CreateAPIError("psbtbroadcasterror", "Something went wrong");
        }    

        [HttpPost("~/api/v1/stores/{storeId}/payouts/{payoutId}/sendconfirm_kk")]
        [Authorize(Policy = Policies.CanManagePullPayments, AuthenticationSchemes = AuthenticationSchemes.Greenfield)]
        public async Task<IActionResult> SendConfirmPayoutPayment_KK(string storeId, string payoutId, CreatePayoutRequest request)
        {     

// kk tbd. check if parameter destination-hex is valid
            var psbtHex = request.Destination; // dirty, in order to reuse CreatePayoutRequest Object, psbthex value is passed as destination parameter            

            // kk own
            var walletId = new WalletId(storeId, "BTC"); // CryptoCode "BTC"

            /******************** WalletSend() *******************/
            var network = _networkProvider.GetNetwork<BTCPayNetwork>(walletId?.CryptoCode); // CryptoCode "BTC"
            //var network = _networkProvider.GetNetwork<BTCPayNetwork>("BTC");
            if (network == null || network.ReadonlyWallet)
                return NotFound();

            //var store = HttpContext.GetStoreData(); // alternative method to get store (but is it always the store with the right storeID??)            
            var store = await _storeRepository.FindStore(walletId.StoreId);
            DerivationSchemeSettings derivationScheme = store?.GetDerivationSchemeSettings(_networkProvider, walletId.CryptoCode);   
      
                    
            var canUseHotWallet = true;                    
            if (canUseHotWallet)
            {                        
                if (derivationScheme.IsHotWallet)
                {
                    var psbt = PSBT.Parse(psbtHex, network.NBitcoinNetwork);                    
                    var jsonRet = psbt.ToString();                    

                    // kk copied source 5 use
                    /******************** FetchTransactionDetails() Start *******************/                            
                    if (!psbt.IsAllFinalized() && !psbt.TryFinalize(out var errors)) {
                        return this.CreateAPIError("psbtsignerror", "Error Signing 5");                                
                    }                            
                    /******************** FetchTransactionDetails() END *******************/

                    // kk copied source 6 use
                    /******************** WalletPSBTReady() Start *******************/      
                    // BROADCAST TRANSACTION                     
                    var transaction = psbt.ExtractTransaction();
                    try
                    {
                        var broadcastResult = await _explorerClientProvider.GetExplorerClient(network).BroadcastAsync(transaction);
                        if (!broadcastResult.Success)
                        {
                            return this.CreateAPIError("psbtbroadcasterror", "Error Broadcast");
                        }
                    }
                    catch (Exception ex)
                    {
                        return this.CreateAPIError("psbtbroadcasterror", ex.Message);
                    }     
                    /******************** WalletPSBTReady() END *******************/                            

                    return Ok();                                             
                    
                }
            }

            
                     
            return this.CreateAPIError("psbtbroadcasterror", "Something went wrong");
        }                   

        [HttpPost("~/api/v1/stores/{storeId}/payouts/{payoutId}/mark-paid")]
        [Authorize(Policy = Policies.CanManagePullPayments, AuthenticationSchemes = AuthenticationSchemes.Greenfield)]
        public async Task<IActionResult> MarkPayoutPaid(string storeId, string payoutId, CancellationToken cancellationToken = default)
        {
            if (!ModelState.IsValid)
                return this.CreateValidationError(ModelState);

            var result = await _pullPaymentService.MarkPaid(new PayoutPaidRequest()
            {
                //TODO: Allow API to specify the manual proof object
                Proof = null,
                PayoutId = payoutId
            });
            var errorMessage = PayoutPaidRequest.GetErrorMessage(result);
            switch (result)
            {
                case PayoutPaidRequest.PayoutPaidResult.Ok:
                    return Ok();
                case PayoutPaidRequest.PayoutPaidResult.InvalidState:
                    return this.CreateAPIError("invalid-state", errorMessage);
                case PayoutPaidRequest.PayoutPaidResult.NotFound:
                    return PayoutNotFound();
                default:
                    throw new NotSupportedException();
            }
        }

        private IActionResult PayoutNotFound()
        {
            return this.CreateAPIError(404, "payout-not-found", "The payout was not found");
        }
        private IActionResult PullPaymentNotFound()
        {
            return this.CreateAPIError(404, "pullpayment-not-found", "The pull payment was not found");
        }
    }
}
