"use strict";

Object.defineProperty(exports, "__esModule", {
	value: true
});

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

var _asn1js = require("asn1js");

var asn1js = _interopRequireWildcard(_asn1js);

var _pvutils = require("pvutils");

var _ResponseBytes = require("./ResponseBytes");

var _ResponseBytes2 = _interopRequireDefault(_ResponseBytes);

var _BasicOCSPResponse = require("./BasicOCSPResponse");

var _BasicOCSPResponse2 = _interopRequireDefault(_BasicOCSPResponse);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _interopRequireWildcard(obj) { if (obj && obj.__esModule) { return obj; } else { var newObj = {}; if (obj != null) { for (var key in obj) { if (Object.prototype.hasOwnProperty.call(obj, key)) newObj[key] = obj[key]; } } newObj.default = obj; return newObj; } }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

//**************************************************************************************

var OCSPResponse = function () {
	//**********************************************************************************
	/**
  * Constructor for OCSPResponse class
  * @param {Object} [parameters={}]
  * @property {Object} [schema] asn1js parsed value
  */

	function OCSPResponse() {
		var parameters = arguments.length <= 0 || arguments[0] === undefined ? {} : arguments[0];

		_classCallCheck(this, OCSPResponse);

		//region Internal properties of the object
		/**
   * @type {Enumerated}
   * @description responseStatus
   */
		this.responseStatus = (0, _pvutils.getParametersValue)(parameters, "responseStatus", OCSPResponse.defaultValues("responseStatus"));

		if ("responseBytes" in parameters)
			/**
    * @type {ResponseBytes}
    * @description responseBytes
    */
			this.responseBytes = (0, _pvutils.getParametersValue)(parameters, "responseBytes", OCSPResponse.defaultValues("responseBytes"));
		//endregion

		//region If input argument array contains "schema" for this object
		if ("schema" in parameters) this.fromSchema(parameters.schema);
		//endregion
	}
	//**********************************************************************************
	/**
  * Return default values for all class members
  * @param {string} memberName String name for a class member
  */


	_createClass(OCSPResponse, [{
		key: "fromSchema",

		//**********************************************************************************
		/**
   * Convert parsed asn1js object into current class
   * @param {!Object} schema
   */
		value: function fromSchema(schema) {
			//region Check the schema is valid
			var asn1 = asn1js.compareSchema(schema, schema, OCSPResponse.schema());

			if (asn1.verified === false) throw new Error("Object's schema was not verified against input data for OCSP_RESPONSE");
			//endregion

			//region Get internal properties from parsed schema
			this.responseStatus = asn1.result.responseStatus;
			if ("responseBytes" in asn1.result) this.responseBytes = new _ResponseBytes2.default({ schema: asn1.result.responseBytes });
			//endregion
		}
		//**********************************************************************************
		/**
   * Convert current object to asn1js object and set correct values
   * @returns {Object} asn1js object
   */

	}, {
		key: "toSchema",
		value: function toSchema() {
			//region Create array for output sequence
			var outputArray = [];

			outputArray.push(this.responseStatus);
			if ("responseBytes" in this) {
				outputArray.push(new asn1js.Constructed({
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 0 // [0]
					},
					value: [this.responseBytes.toSchema()]
				}));
			}
			//endregion

			//region Construct and return new ASN.1 schema for this object
			return new asn1js.Sequence({
				value: outputArray
			});
			//endregion
		}
		//**********************************************************************************
		/**
   * Convertion for the class to JSON object
   * @returns {Object}
   */

	}, {
		key: "toJSON",
		value: function toJSON() {
			var _object = {
				responseStatus: this.responseStatus.toJSON()
			};

			if ("responseBytes" in this) _object.responseBytes = this.responseBytes.toJSON();

			return _object;
		}
		//**********************************************************************************
		/**
   * Get OCSP response status for specific certificate
   * @param {Certificate} certificate
   * @param {Certificate} issuerCertificate
   * @returns {*}
   */

	}, {
		key: "getCertificateStatus",
		value: function getCertificateStatus(certificate, issuerCertificate) {
			//region Initial variables
			var basicResponse = void 0;

			var result = {
				isForCertificate: false,
				status: 2 // 0 = good, 1 = revoked, 2 = unknown
			};
			//endregion

			//region Check that "ResponseBytes" contain "OCSP_BASIC_RESPONSE"
			if ("responseBytes" in this === false) return result;

			if (this.responseBytes.responseType !== "1.3.6.1.5.5.7.48.1.1") // id-pkix-ocsp-basic
				return result;

			try {
				var asn1Basic = asn1js.fromBER(this.responseBytes.response.valueBlock.valueHex);
				basicResponse = new _BasicOCSPResponse2.default({ schema: asn1Basic.result });
			} catch (ex) {
				return result;
			}
			//endregion

			return basicResponse.getCertificateStatus(certificate, issuerCertificate);
		}
		//**********************************************************************************
		/**
   * Make a signature for current OCSP Response
   * @param {Object} privateKey Private key for "subjectPublicKeyInfo" structure
   * @param {string} [hashAlgorithm] Hashing algorithm. Default SHA-1
   * @returns {Promise}
   */

	}, {
		key: "sign",
		value: function sign(privateKey, hashAlgorithm) {
			//region Check that ResponseData has type BasicOCSPResponse and sign it
			if (this.responseBytes.responseType === "1.3.6.1.5.5.7.48.1.1") {
				var asn1 = asn1js.fromBER(this.responseBytes.response.valueBlock.valueHex);
				var basicResponse = new _BasicOCSPResponse2.default({ schema: asn1.result });

				return basicResponse.sign(privateKey, hashAlgorithm);
			}

			return Promise.reject("Unknown ResponseBytes type: " + this.responseBytes.responseType);
			//endregion
		}
		//**********************************************************************************
		/**
   * Verify current OCSP Response
   * @returns {Promise}
   */

	}, {
		key: "verify",
		value: function verify() {
			//region Check that ResponseBytes exists in the object
			if ("responseBytes" in this === false) return Promise.reject("Empty ResponseBytes field");
			//endregion

			//region Check that ResponceData has type BasicOCSPResponse and verify it
			if (this.responseBytes.responseType === "1.3.6.1.5.5.7.48.1.1") {
				var asn1 = asn1js.fromBER(this.responseBytes.response.valueBlock.valueHex);
				var basicResponse = new _BasicOCSPResponse2.default({ schema: asn1.result });

				return basicResponse.verify();
			}

			return Promise.reject("Unknown ResponseBytes type: " + this.responseBytes.responseType);
			//endregion
		}
		//**********************************************************************************

	}], [{
		key: "defaultValues",
		value: function defaultValues(memberName) {
			switch (memberName) {
				case "responseStatus":
					return new asn1js.Enumerated();
				case "responseBytes":
					return new _ResponseBytes2.default();
				default:
					throw new Error("Invalid member name for OCSPResponse class: " + memberName);
			}
		}
		//**********************************************************************************
		/**
   * Compare values with default values for all class members
   * @param {string} memberName String name for a class member
   * @param {*} memberValue Value to compare with default value
   */

	}, {
		key: "compareWithDefault",
		value: function compareWithDefault(memberName, memberValue) {
			switch (memberName) {
				case "responseStatus":
					return memberValue.isEqual(OCSPResponse.defaultValues(memberName));
				case "responseBytes":
					return _ResponseBytes2.default.compareWithDefault("responseType", memberValue.responseType) && _ResponseBytes2.default.compareWithDefault("response", memberValue.response);
				default:
					throw new Error("Invalid member name for OCSPResponse class: " + memberName);
			}
		}
		//**********************************************************************************
		/**
   * Return value of asn1js schema for current class
   * @param {Object} parameters Input parameters for the schema
   * @returns {Object} asn1js schema object
   */

	}, {
		key: "schema",
		value: function schema() {
			var parameters = arguments.length <= 0 || arguments[0] === undefined ? {} : arguments[0];

			//OCSPResponse ::= SEQUENCE {
			//    responseStatus         OCSPResponseStatus,
			//    responseBytes          [0] EXPLICIT ResponseBytes OPTIONAL }
			//
			//OCSPResponseStatus ::= ENUMERATED {
			//    successful            (0),  -- Response has valid confirmations
			//    malformedRequest      (1),  -- Illegal confirmation request
			//    internalError         (2),  -- Internal error in issuer
			//    tryLater              (3),  -- Try again later
			//    -- (4) is not used
			//    sigRequired           (5),  -- Must sign the request
			//    unauthorized          (6)   -- Request unauthorized
			//}

			/**
    * @type {Object}
    * @property {string} [blockName]
    * @property {string} [responseStatus]
    * @property {string} [responseBytes]
    */
			var names = (0, _pvutils.getParametersValue)(parameters, "names", {});

			return new asn1js.Sequence({
				name: names.blockName || "OCSPResponse",
				value: [new asn1js.Enumerated({ name: names.responseStatus || "responseStatus" }), new asn1js.Constructed({
					optional: true,
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 0 // [0]
					},
					value: [_ResponseBytes2.default.schema(names.responseBytes || {
						names: {
							blockName: "responseBytes"
						}
					})]
				})]
			});
		}
	}]);

	return OCSPResponse;
}();
//**************************************************************************************


exports.default = OCSPResponse;
//# sourceMappingURL=OCSPResponse.js.map